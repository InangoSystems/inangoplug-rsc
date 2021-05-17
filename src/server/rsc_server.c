/*
################################################################################
#
#  Copyright 2019-2021 Inango Systems Ltd.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
################################################################################
*/
#include <arpa/inet.h>
#include <getopt.h>
#include <linux/limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <rsc_protocol.h>

#include "rsc_server.h"

#include "rsc_logger.h"
#include "rsc_proc.h"
#include "rsc_threads.h"
#include "rsc_version.h"

#ifdef RSC_GIT_COMMIT
    #define GIT_REV_PLACEHOLDER  ", commit: \"%s\""
    #define GIT_REV              RSC_GIT_COMMIT
#else
    #define GIT_REV_PLACEHOLDER  "%s"
    #define GIT_REV              ""
#endif

/* TODO: gIpv6 is used locally while listening setup - no need to be global */
int gIpv6 = 0;
/*descriptor of open TCP-socket*/
static int newsockfd = -1;
/*the socket defence mutex*/
pthread_mutex_t socketMutex;

static volatile int isInterrupted = 0;

static void SigIntHandler(int value)
{
    (void)value;
    fprintf(stderr, "\n-- Received SIGINT: pid = %d\n", getpid());
    isInterrupted = 1;
}

int RscIsInterrupted(void)
{
    return isInterrupted;
}

/* tries to receive while either not all received or error happened.
 * return =-1 if error or =len if all data received
 */
static ssize_t RecvFull(const void *buf, size_t len, int flags)
{
    ssize_t resRecv;
    size_t numRecvByte = 0;

    do
    {
        resRecv = recv(newsockfd, (char*)buf + numRecvByte, len - numRecvByte, flags);
        if (resRecv == -1)
        {
            RSC_LOG_ERRNO("Error on recv data");
            break;
        }
        /*if connection was closed*/
        if (resRecv == 0)
        {
            break;
        }
        numRecvByte += resRecv;
    }while(numRecvByte < len);

    if (numRecvByte < len)
        return -1;

    return len;
}


/* tries send while either not all sent or error happened.
 * return =-1 if error or =len if all data sent
 */
static ssize_t SendFull(const void *buf, size_t len, int flags)
{
    ssize_t resSend;
    size_t numSendByte = 0;

    pthread_mutex_lock(&socketMutex);
    do
    {
        resSend = send(newsockfd, (char*)buf + numSendByte, len - numSendByte, flags);
        if (resSend == -1)
        {
            RSC_LOG_ERRNO("Error on send data");
            break;
        }
        numSendByte += resSend;
    }while(numSendByte < len);
    pthread_mutex_unlock(&socketMutex);

    if (numSendByte < len)
        return -1;

    return len;
}

/* receive 'len' byte to 'buf' from RSC-connection.
 * return =-1 if error or =len if all data received
 */
ssize_t RscRecv(const void *buf, size_t len)
{
    return RecvFull(buf, len, MSG_WAITALL);
}

/* send 'len' byte from 'buf' to RSC-connection.
 * return =-1 if error or =len if all data sent
 */
ssize_t RscSend(const void *buf, size_t len)
{
    return SendFull(buf, len, MSG_NOSIGNAL);
}

static int RscSetSockOptInt(int fd, int level, int optname, int optval)
{
    return setsockopt(fd, level, optname, &optval, sizeof(optval));
}

static int RscSetClientSockOptions(int fd)
{
    if (RscSetSockOptInt(fd, SOL_SOCKET, SO_KEEPALIVE, SO_KEEPALIVE_VALUE) < 0)
    {
        RSC_LOG_ERRNO("ERROR setsockopt(SO_KEEPALIVE) failed");
        return -1;
    }

    if (RscSetSockOptInt(fd, IPPROTO_TCP, TCP_KEEPCNT, TCP_KEEPCNT_VALUE) < 0)
    {
        RSC_LOG_ERRNO("ERROR setsockopt(TCP_KEEPCNT) failed");
        return -1;
    }

    if (RscSetSockOptInt(fd, IPPROTO_TCP, TCP_KEEPINTVL, TCP_KEEPINTVL_VALUE) < 0)
    {
        RSC_LOG_ERRNO("ERROR setsockopt(TCP_KEEPINTVL) failed");
        return -1;
    }

    if (RscSetSockOptInt(fd, IPPROTO_TCP, TCP_KEEPIDLE, TCP_KEEPIDLE_VALUE) < 0)
    {
        RSC_LOG_ERRNO("ERROR setsockopt(TCP_KEEPIDLE) failed");
        return -1;
    }

    if (RscSetSockOptInt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, TCP_USER_TIMEOUT_VALUE) < 0)
    {
        RSC_LOG_ERRNO("ERROR setsockopt(TCP_USER_TIMEOUT) failed");
        return -1;
    }

    if (RscSetSockOptInt(fd, IPPROTO_TCP, TCP_NODELAY, TCP_NODELAY_VALUE) < 0)
    {
        RSC_LOG_ERRNO("ERROR setsockopt(TCP_NODELAY) failed");
        return -1;
    }

    return 0;
}

/*connection and running of clients processing*/
static int RscServerListen(const char *interfaceName, const char *ipLocal, uint16_t port)
{
    pid_t pid;
    int sockfd;
    struct sockaddr_in6 servAddr6;
    struct sockaddr_in6 clientAddr6;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t servAddrLen = sizeof(servAddr);
    socklen_t clientAddrLen = sizeof(clientAddr);
    struct sockaddr *servAddrPtr = (struct sockaddr *)(&servAddr);
    struct sockaddr *clientAddrPtr = (struct sockaddr *)(&clientAddr);
    /*open and configure socket*/
    sockfd = socket(gIpv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        RSC_LOG_ERRNO("ERROR opening socket");
        return 1;
    }

    if (RscSetSockOptInt(sockfd, SOL_SOCKET, SO_REUSEADDR, SO_REUSEADDR_VALUE) < 0)
    {
        RSC_LOG_ERRNO("ERROR setsockopt(SO_REUSEADDR) failed");
        return 1;
    }

    if (interfaceName)
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interfaceName, IF_NAMESIZE) < 0)
        {
            RSC_LOG_ERRNO("ERROR setsockopt(SO_BINDTODEVICE) failed");
            return 1;
        }
    }

    if (gIpv6)
    {
        memset((char *) &servAddr6, 0, sizeof(servAddr6));
        servAddr6.sin6_family = AF_INET6;
        servAddr6.sin6_addr = in6addr_any;
        servAddr6.sin6_port = htons(port);
        servAddrPtr = (struct sockaddr *)(&servAddr6);
        clientAddrPtr = (struct sockaddr *)(&clientAddr6);
        servAddrLen = sizeof(servAddr6);
        clientAddrLen = sizeof(clientAddr6);
    }
    else
    {
        memset((char *) &servAddr, 0, sizeof(servAddr));
        servAddr.sin_family = AF_INET;
        servAddr.sin_addr.s_addr = INADDR_ANY;
        servAddr.sin_port = htons(port);
    }

    if (ipLocal)
    {/*if IP address was input by command line*/
        if (inet_pton(gIpv6 ? AF_INET6 : AF_INET, ipLocal,
            gIpv6 ? (void *)(&(servAddr6.sin6_addr)) : (void *)(&(servAddr.sin_addr))) <= 0)
        {
            RSC_LOG_ERRNO("ERROR set IP address");
            return 1;
        }
    }

    if (bind(sockfd, servAddrPtr, servAddrLen) < 0)
    {
        RSC_LOG_ERRNO("ERROR on binding IP address");
        return 1;
    }

    /*ignore signals about end of childs work*/
    signal(SIGCHLD, SIG_IGN);
    /* Now start listening for the clients*/
    if (listen(sockfd, 5) < 0)
    {
        RSC_LOG_ERRNO("ERROR on listen");
        return 1;
    }

    while (!isInterrupted)
    {
        newsockfd = accept(sockfd, clientAddrPtr, &clientAddrLen);

        if (newsockfd < 0)
        {
            RSC_LOG_ERRNO("ERROR on accept");
            continue;
        }

        if (RscSetClientSockOptions(newsockfd) < 0)
        {
            RSC_LOG_ERROR("ERROR failed to set options for accepted client socket - closing the connection");
            close(newsockfd);
            continue;
        }

        /*make child process for processing client*/
        pid = fork();
        if (pid == -1)
        {
            RSC_LOG_ERRNO("ERROR on fork");
        }
        else if (pid == 0)
        {
            /* processing client in child process */
            uint32_t defaultThreadId;
            int      defaultEventFd;

            RscLoggerChildProcessSetup();

            close(sockfd);

            RscLoggerIdentifyThread(MAIN_THREAD_ID);

            if (0 != pthread_mutex_init(&socketMutex, NULL))
            {
                RSC_LOG_ERRNO("ERROR mutex initialisation");
                /*on the some linux forked processes don't end after call exit() but end correctly after _exit()*/
                _exit(1);
            }

            if (RSC_RESULT_OK != RscCreateThread(&defaultThreadId, &defaultEventFd))
            {
                pthread_mutex_destroy(&socketMutex);
                RSC_LOG_ERRNO("ERROR can't run the default syscall processing thread");
                /*on the some linux forked processes don't end after call exit() but end correctly after _exit()*/
                _exit(1);
            }

            RscProcessingClient(defaultEventFd);

            close(newsockfd);

            RscStopThread(defaultThreadId);
            pthread_mutex_destroy(&socketMutex);

            /* on some Linux systems forked processes don't terminate after exit() but terminate correctly after _exit() */
            _exit(0);
        }

        close(newsockfd);
   } /* end of while */
   return 0;
}


/*output short description and usage of server*/
static void RscUsage(void)
{
    printf("Usage:\n");
    printf("    rsc-server -v\n");
    printf("    rsc-server -h\n");
    printf("    rsc-server [-6] [-i<net_Interface>] [-a<ip_Address>] [-p<Port>] [-d<verbosity_bit-mask>] [-f<name>] [-s] [-c<count>] [-m<size>]\n");
    printf("Where:\n");
    printf("    -6 - listen on IPv6\n");
    printf("    -i<net_Interface> - set the listening net interface\n");
    printf("    -a<ip_Address> - set the listening IP address\n");
    printf("    -p<Port> - set the port, default sets to %d\n", RSC_DEFAULT_PORT);
    printf("    -d<verbosity_bit-mask> - set debug log verbosity levels as sum of the following distinct numbers:\n");
    printf("        1 - warning\n");
    printf("        2 - informational\n");
    printf("        4 - debug\n");
    printf("        NOTE: error level is always turned on\n");
    printf("    -f<name> - log file name (may be including full path, max length is %d)\n", MAX_LOG_FILE_PATH_SIZE - 1);
    printf("    -s - silent mode - no console output\n");
    printf("    -c<count> - rotation file count (1 <= count <= 9, default is 1)\n");
    printf("    -m<size> - log file size limit in bytes (max is %d (used by default), min is %d)\n", MAX_LOG_FILE_SIZE, MIN_LOG_FILE_SIZE);
    printf("    -v - print version\n");
    printf("    -h - print this page\n");
}

static void RscPrintVersion(void)
{
    printf("rsc-server version %s\n", RSC_VERSION);
#ifdef RSC_GIT_COMMIT
    if (strlen(RSC_GIT_COMMIT))
        printf("git commit: %s\n", RSC_GIT_COMMIT);
#endif
    printf("built at %s %s\n", __TIME__, __DATE__);
}

int main(int argc, char * argv[])
{
    char         ipLocal[MAX_LEN_IP] = "";
    char         interfaceName[IF_NAMESIZE] = "";
    char        *ipLocalPtr = NULL;
    char        *interfaceNamePtr = NULL;
    uint16_t     port = RSC_DEFAULT_PORT;
    int          opt;
    long int     tempPort;
    LogLevels    logLevels;
    LogConf_t   *logConf = RscLoggerConf();
    char        *endPtr;
    int          rc = 0;

    signal(SIGINT, SigIntHandler);

    do
    {
        opt = getopt(argc, argv, "vd:h6p:a:i:f:sc:m:");
        switch (opt)
        {
        case -1:
            break;
        case 'h':
            RscUsage();
            return 0;
        case 'd':
            logLevels = strtoul(optarg, &endPtr, 0);
            if (*endPtr != '\0' || logLevels > UINT16_MAX)
            {
                fprintf(stderr, "Invalid log levels mask: %s\n", optarg);
                RscUsage();
                return 2;
            }
            RscLoggerSetLevels(logLevels);
            break;
        case '6':
            gIpv6 = 1;
            break;
        case 'p':
            tempPort = strtol(optarg, NULL, 0);
            if ((tempPort < 0) || (tempPort > UINT16_MAX))
            {
                fprintf(stderr, "Undefined port: %s\n", optarg);
                RscUsage();
                return 2;
            }
            port = (uint16_t)tempPort;
            break;
        case 'i':
            strcpy(interfaceName, optarg);
            interfaceNamePtr = interfaceName;
            break;
        case 'a':
            strcpy(ipLocal, optarg);
            ipLocalPtr = ipLocal;
            break;
        case 'f':
            if (strlen(optarg) >= sizeof(logConf->fileName))
            {
                fprintf(stderr, "Log file path is too long: '%s'\n", optarg);
                RscUsage();
                return 2;
            }
            strcpy(logConf->fileName, optarg);
            logConf->logToFile = 1;
            break;
        case 's':
            logConf->logToConsole = 0;
            break;
        case 'c':
            logConf->rotateFileCount = strtol(optarg, &endPtr, 0);
            if (*endPtr != '\0' || logConf->rotateFileCount < 1 || logConf->rotateFileCount > MAX_LOG_ROTATE_FILE_COUNT)
            {
                fprintf(stderr, "Invalid rotate file count value: %s\n", optarg);
                RscUsage();
                return 2;
            }
            break;
        case 'm':
            logConf->fileSizeLimit = strtol(optarg, &endPtr, 0);
            if (*endPtr != '\0' || logConf->fileSizeLimit > MAX_LOG_FILE_SIZE || logConf->fileSizeLimit < MIN_LOG_FILE_SIZE)
            {
                fprintf(stderr, "Log file size limit is invalid: %s\n", optarg);
                RscUsage();
                return 2;
            }
            break;
        case 'v':
            RscPrintVersion();
            return 0;
        default:
            RscUsage();
            return 2;
        }
    } while (opt != -1);

    if (!RscLoggerStart())
    {
        fprintf(stderr, "Failed to start logger\n");
        return 1;
    }

    RscLoggerIdentifyThread(MAIN_THREAD_ID);

    RSC_LOG_INFO("-- RSC Server has been started (version: \"%s\"" GIT_REV_PLACEHOLDER ", build-time: \"%s %s\")", RSC_VERSION, GIT_REV, __TIME__, __DATE__);

    if (ipLocalPtr)
        RSC_LOG_INFO("IP  : %s", ipLocal);
    RSC_LOG_INFO("Port: %d", port);

    if (RscThreadsDataInit() != RSC_RESULT_OK)
        RSC_LOG_ERROR("Threads data initialisation error");
    else
        rc = RscServerListen(interfaceNamePtr, ipLocalPtr, port);

    RSC_LOG_INFO("-- RSC Server has been stopped");

    RscLoggerStop();

    RscThreadsDataDeinit();
    return rc;
}

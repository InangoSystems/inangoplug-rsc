# RSC

RSC stands for Remote Syscalls and involves two hosts:

* Linux client host that runs an unmodified user application
* Linux server host that actually executes system calls that were issued by the user application (as if they come from local process), mostly CPE/board with limited resources

So RSC is about running user application on client host so as if it is ran on server host actually.

################################################################################
#
#  Copyright 2019 Inango Systems Ltd.
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

GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)
GIT_DIFF := $(shell git diff --shortstat 2> /dev/null | tail -n1 )

ifeq ("$(GIT_COMMIT)", "")
	GIT_COMMIT := ""
else
	ifneq ("$(GIT_DIFF)", "")
		GIT_COMMIT += dirty
	endif
endif

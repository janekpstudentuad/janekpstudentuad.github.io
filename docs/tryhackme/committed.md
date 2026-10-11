---
tags:
  - tryhackme
  - challenge
  - easy
  - defensive
  - linux
  - git
---

# Committed
![Committed logo](logos/committed.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Committed](https://tryhackme.com/room/committed)  

## Description
"Oh no, not again! One of our developers accidentally committed some sensitive code to our GitHub repository. Well, at least, that is what they told us... the problem is, we don't remember what or where! Can you track down what we accidentally committed?"

## Environment and Artifacts provided
`commited.zip` archive

## Task: 
Uncover the flag in the repository.
### Artifacts examined
`commited.zip` archive
### Analysis
```bash
unzip commited.zip
cd commited
ls -al
```
```
drwxrwxr-x 8 ubuntu ubuntu 4096 Feb 13  2022 .git
-rw-rw-r-- 1 ubuntu ubuntu  393 Feb 13  2022 Readme.md
-rw-rw-r-- 1 ubuntu ubuntu  982 Feb 13  2022 main.py
```
Directory contents reveal this is the git repository referred to in the description.  
Examine repo history with `git log --all`:  
```
commit 28c36211be8187d4be04530e340206b856198a84 (HEAD -> master)
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:49:32 2022 -0800

    Finished

commit 4e16af9349ed8eaa4a29decd82a7f1f9886a32db (dbint)
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:48:08 2022 -0800

    Reminder Added.

commit c56c470a2a9dfb5cfbd54cd614a9fdb1644412b5
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:46:39 2022 -0800

    Oops

commit 3a8cc16f919b8ac43651d68dceacbb28ebb9b625
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:45:14 2022 -0800

    DB check

commit 6e1ea88319ae84175bfe953b7791ec695e1ca004
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:43:34 2022 -0800

    Note added

commit 9ecdc566de145f5c13da74673fa3432773692502
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:40:19 2022 -0800

    Database management features added.

commit 26bcf1aa99094bf2fb4c9685b528a55838698fbe
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:32:49 2022 -0800

    Create database logic added

commit b0eda7db60a1cb0aea86f053816a1bfb7e2d6c67
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:30:43 2022 -0800

    Connecting to db logic added

commit 441daaaa600aef8021f273c8c66404d5283ed83e
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:28:16 2022 -0800

    Initial Project.
```
Examine repo contents of commit *before* comment of "Oops" to identify mistake corrected:  
```bash
git checkout 3a8cc16f919b8ac43651d68dceacbb28ebb9b625
ls -al
```
```
drwxrwxr-x 8 ubuntu ubuntu 4096 Oct 11 14:01 .git
-rw-r--r-- 1 ubuntu ubuntu   83 Oct 11 14:01 Note
-rw-r--r-- 1 ubuntu ubuntu  363 Oct 11 14:01 Readme.md
-rw-r--r-- 1 ubuntu ubuntu 1108 Oct 11 14:01 main.py
```
Contents of `main.py` reveal hardcoded password containing flag.

### Answer
??? success "Discover the flag in the repository!"
	flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}

**Tools Used**  
`git`

**Date completed:** 11/10/26  
**Date published:** 11/10/26
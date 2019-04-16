# GOMerkel
Small Merkle Hash Tree implementation in GO

Introduction
------------
This is a small implementation of a Merkle Hash Tree in GOLang. A Merkle Hash tree is a method of data storage where file hashes are generated and a tree of these hashes are made iteratively upon the hashes up until the main the root node. This is very advantageous as it allows us to validate a data set in O(1) time (just store and check the root node) requires little memory (just tree of hashes) and fast insertion.

Notes
------------
This code base is meant to demonstrate the theoretical performance of the Tree using SHA-256 as the encryption method. Here a bash script is used to create random 1KB files which the code will find these files, calculate hashes and place them into a temporary list and then generate a tree. The program will output the number of files found, and the amount of time each function took to execute (Setup, Prove, Verify and Insert). Due to limited time the update/insertion function was simple in that a data entry is inserted into the list data structure and then regenerate a new tree. As a result we cannot really take advantage of the fast insertion aspect unfortunately and you will clearly see the close relationship that update has with the number of files

How To Use (Linux)
------------
Ensure that you have GOLang installed. Execute the Bash script (you may edit it to choose the number of files to generate). Then execute: go run main.go

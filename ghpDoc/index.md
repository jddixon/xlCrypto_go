<h1 class="libTop">xlCrypto_go</h1>

The crypto library for
[xlattice_go.](https://jddixon.github.io/xlattice_go)

The library contains functions for

* an implementation of the XLattice **BuildList**
, a tool for describing and verifying the integrity of files systems
* PKCS7 padding
* RSA public and private key serialization and deserialization
* RSA/SHA1 digital signatures

## BuildList

A **BuildList** consists of

* a serialized RSA public key
* a title
* a date in a standardized format
* a number of content lines preceded and followed by `# BEGIN CONTENT` and `# END CONTENT #` lines
* optionally a digital signature

The content lines consist of an indented list of the directory tree
involved, with the names of files and subdirectories in a directory
indented one space deeper than their parent.  File names are accompanied
by their SHA hash as a hex string. See the
[NLHTree specs](https://jddixon.github.io/nlhtree_py)
specs for more information on this encoding scheme.:

For more detail on the XLattice BuildList look
[here](https://jddixon.github.io/xlattice/buildList.html).

# Project Status

Stable although skeletal.  All tests succeed.


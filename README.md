

# Video Integrity Verification using Elliptic Curve Digital Signature Algorithm on blockchian framework.
If you find the source code useful for academic research, you are highly encouraged to cite the following paper:

L. Lawrence, R. Shreelekshmi, Chained digital signature for the improved video integrity verification, in:
Modern Management based on Big Data II and Machine Learning and Intelligent Systems III – Proceedings of MMBD 2021 and MLIS 2021, China, Vol. 341 of Frontiers in Artificial Intelligence and Applications,
IOS Press, 2021, pp. 520–526. doi:10.3233/FAIA210284.

## Abstract

The recorded videos from the surveillance cameras can be used as potential evidence in forensic applications. These videos can be easily manipulated or tampered with video editing tools without leaving visible clues. Hence integrity verification is essential before using the videos as evidence. Existing methods mostly depend on the analysis of video data stream and video container for tampering detection. This scheme discusses an active video integrity verification method using Elliptic Curve Cryptography and blockchain. The method uses Elliptic Curve Digital Signature Algorithm for calculating digital signature for video content and previous block. The digital signature of the encoded video segment (video content with predetermined size) and that of previous block are kept in each block to form an unbreakable chain. Our method does not consider any coding or compression artifacts of the video file and can be used on any video type and is tested on public-available standard videos with varying sizes and types. The proposed integrity verification scheme has better detection capabilities towards different types of alterations like insertion, copy-paste and deletion and can detect any type of forgery. This method is faster and more resistant to brute force and collision attacks in comparison to existing recent blockchain method.

## Authors

Linju Lawrence, mail Id: linjulawrence680@gmail.com, linjulawrence680@cet.ac.in
Dr. Shreelekshmi R., mail Id: shreelekshmi@cet.ac.in

## Code

Our code is organized as
-SigLVIV.c
-videos folder
-Results.txt

SigLVIV.c performs the key generation, signature generation, blockchain storage and verification of the signatures for the test videos. Copy videos
from the videos folder to the folder containing SigLVIV.c. Results.txt contains sample output.

## Prerequisites

The SigLVIV is developed in C language and uses gcc compiler. OpenSSL cryptographic library and libssl-dev package must be installed. The program is compiled by,
$ gcc SigLVIV.c -o siglviv -lssl -lcrypto
and run by
./siglviv

We conducted experiments on a PC having Intel Core i7-45U CPU@1.8GHz×4 and 12 GB RAM. The test videos from different bench mark datasets such as VIRAT,
SULFA and Derf's collections and five publicly available video segments from YouTube are used.
For each test videos, the experiments run about 30 times and the average value is given.

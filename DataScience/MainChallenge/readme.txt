Main Challenge
0

Welcome to the Data Science for Cyber Defense Challenge!

In this challenge you are presented with network logs of a mid-size organization. 
An anonymous source reported that the network has been compromised by not just one, but 4 different types of malware. 
Your objective is to analyze the logs and discover the infected endpoints.

Each correct identification of endpoints that have been attacked by a given malware type will grant you a flag.

All together there are 4 flags, corresponding to the 4 malware types. To retrieve a flag , submit your solution here:

Submit

To download the challenge.zip file:

http://shieldchallenges.com/files/challenge.zip

The network logs are given in the challenge.csv file which contains the following columns:

timestamp
src_ip
dst_ip
src_port
dst_port
protocol
payload
Submission Guidelines

Submission of suspected endpoints should be in the example submission_example.csv format below. 
Each submission should contain the endpoints infected by a single malware type. 
Note that a single endpoint may be infected by at most one malware type.

Scoring

The submission score is the maximal F1 score https://en.wikipedia.org/wiki/F-score corresponding to any of the four malware types, 
and is calculated as follows: drawing

A minimal score of 0.8 is required in order to gain the flag which corresponds to the best-detected malware type.

Can you gain all four flags?


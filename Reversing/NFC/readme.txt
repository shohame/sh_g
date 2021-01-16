NFC
200

Our target adopted a new way to keep sensitive information! 
They use secure NFC tags to keep secure and confidential information inside them.

We managed to place a strong NFC reader near our target’s secret NFC tag. 
Now we want to communicate with the that tag and extract the secret information from it.

In order to connect to our reader and send commands to the tag, you just need to open a TCP socket to:

nfc.shieldchallenges.com 80

Each message you send on this socket will be transferred to the NFC tag, 
and the response from the tag will be sent back to you on that same socket.

In addition, our sources equipped us with some information that may help you to communicate with the tag and 
extract the secret information from it:

A secret document from our target (attached).

An authentic message sent to the NFC tag. Due to a low signal, we managed to extract only 5 bytes from the message. 
The message is presented below (X stands for an unknown nibble).

           1BXXXXBEAF4930
The secret information you need to extract is located somewhere in the memory space of the tag, and its size is 16 characters.

Good luck! We trust you!
Warmup
100

You have received a black box with a small note:  Your goal is to figure out the interleaver permutation. 
In other words: interleaver(1,2,3,…,254,255,256) -> ?

Use the Matlab command: B = blackBox(); to create an instance of the blackBox object. 
Then use the Matlab command: outputVector = B(inputVector);
 assign the blackBox output to any given input as many times as you want.

After you finish, put your interleaver vector in a vector called "interleaver" and execute the following command:

finalAnswer = sum(interleaver(:)./(1:256).')

Submit your result, which should be a number between 0 and 1000, with a precision of 4 digits after the decimal point.
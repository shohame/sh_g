NLP
250

A jaded attacker, who installed a malware on your computer, 
was able to access all your text files and a managed to encrypt them all. 
By analysing the timestamps, he used the last document you worked on and iterated over it sentence by sentence, 
and for each sentence used a pre-trained BERT model to create a 768D embedding vector which was persisted to permanent storage.

The vector he created was computed using the 'bert-base-multilingual-uncased' model. 
The vector is an average of the second-to-last hidden layer outputs, over all tokens (including special ones).

Subsequently, he erased the document from your hard-drive and kept a copy to himself. 
Knowing how significant the loss of the document is to you, he challenges you to solve a riddle to gain back access to your files.

He provides you with a single feature vector (a 768d embedding), of a specific sentence in the document.

He guarantees that if you are able to find the actual sentence, he will unlock your hard drive.

Each sentence in the original document had a line number associated with it, you are to provide him with that number.

A big hint to find this number is hidden in the first image file provided with this challenge. 
The second txt file is the BERT embedding.
On count being the number of times the key loop runs and not the max(PK2[]).
But since the guessed subkey is indeed calc on the basis of max(PK2[]), we can say that it might just be a coincidence that "max(PK2)=count"
why is count a key count because it just tells us how many times the key loop runs. Why are we so sure that for all these runs there is one key that always works and hence its count equals the no. of times we enter the key loop.

1. No matches in case of conflicting dex and dex2. VERIFIED

2. Always match in case of non-conflicting dex and dex2. VERIFIED
 

 // to test
1. and 2. imply that 
	matchSimulSB is either 0 or 255

conflict bw dex and dex2 happens iff matchSimulSB = 0

conflict implies COUNT =0
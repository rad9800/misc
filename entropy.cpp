#include <stdio.h>

/*++
* 
* Packed malware has high entropy. It is not uncommon for EDRs to
* use the entropy of a PE as a measure of its potential malicious 
* activity. Entropy is just the measure of randomness.
* 
* One common way to fix entropy was to concatenate Windows System
* DLLs or the first chapter of Harry Potter and the Philosopher's 
* Stone. This works when the bytes are similar and the entropy of 
* the concatenated are lower than that of the PE file.
* 
* A simple solution is to just define a array populated with zero
* or another character/value. This will allow us to fundamentally
* get lower entropy values for the overall PE file and the .rdata
* section.
* 
--*/


template<unsigned int N, typename T, T value>
struct E {
    constexpr E() : array() {
        for (unsigned int i = 0; i < N; i++) {
            array[i] = (T)value;
        }
    }
    T array[N];
};

constexpr auto e = E<4000, long long, 0>();


/*++
* 
* Before:
* // E<4, long long, 0>();
* 
* - Total Entropy   : 4.658898546328656
* - Size            : 10.8 KB
* 
* - Name     .text
* - Size     3584 bytes
* - Entropy  5.757317522100548
* 
* - Name     .rdata
* - Size     4096 bytes
* - Entropy  3.950817412562706
* 
* 
* After:
* // E<4000, long long, 0>();
* - Total Entropy   : 1.4966239940876724
* - Size            : 42.5 KB
* - Sections        :
* 
* - Name     .text
* - Size     3584 bytes
* - Entropy  5.783502669099978
* - Name     .rdata
* - Size     35840 bytes
* - Entropy  0.6449460947480491     
* This large low entropy section biases our total entropy
* 
--*/

int main() {
    int total = 0;

    // Use it, pointlessly, or for a reason but don't let it
    // get optimized out by the compiler
    for (auto x : e.array)
        total += x;
    
    return total;   // prevent compiler optimizing it out on /O1 /O2
}

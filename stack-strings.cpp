#include <array>
#include <cstddef>
#include <algorithm>
#include <utility>
#include <stdio.h>

template<typename T, size_t N>
constexpr auto stack(const T(&str)[N]) 
{
    std::array<T, N> ret{};
    std::copy(std::begin(str), std::end(str), ret.begin());
    return ret;
}

/*++
* 
* Setup stack strings in an easier fashion using constexpr macros
* Some may get optimized into mmx registers some many not
* 
* Credit to @JonasLyk for pushing me in the right direction and 
* his nt code 
* 
--*/
int main()
{

    printf("hello world : plaintext \n");

    const char stack_0[] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' ,'\0'};
    printf("%s\n", stack_0);

    // works as a stack string
    constexpr auto stack_1 = stack(L"hello world : widechar");  
    static_assert(std::is_same_v<decltype(stack_1), const std::array<wchar_t, 23>>);
    printf("%S\n", &stack_1[0]);

    // gets optimized to xmmword
    // this means the first 128 of the strings will be made available
    // movdqa  xmm0, XMMWORD PTR __xmm@6863203a20646c726f77206f6c6c6568
    // lea     rdx, QWORD PTR stack_2$[rbp-128]
    // lea     rcx, OFFSET FLAT:`string'
    // mov     WORD PTR stack_2$[rbp-112], 29281 ; 00007261H
    constexpr auto stack_2 = stack("hello world : char");   
    static_assert(std::is_same_v<decltype(stack_2), const std::array<char, 19>>);
    printf("%s\n", &stack_2[0]);

    return 0;
}

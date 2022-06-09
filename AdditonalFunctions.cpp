/*

This file contains additional functions we will need in the future

Sources used:
https://www.geeksforgeeks.org/program-decimal-hexadecimal-conversion/
https://www.educative.io/edpresso/how-to-convert-a-number-from-decimal-to-hexadecimal-in-cpp
*/

#include <stdio.h>
#include <iostream>
using namespace std;

// function to convert decimal to hexadecimal
void decToHexa(int n)
{
    // char array to store hexadecimal number
    char hexaDeciNum[100];
 
    // counter for hexadecimal number array
    int i = 0;
    while (n != 0) {
        // temporary variable to store remainder
        int temp = 0;
 
        // storing remainder in temp variable.
        temp = n % 16;
 
        // check if temp < 10
        if (temp < 10) {
            hexaDeciNum[i] = temp + 48;
            i++;
        }
        else {
            hexaDeciNum[i] = temp + 55;
            i++;
        }
 
        n = n / 16;
    }
 
    // printing hexadecimal number array in reverse order
    for (int j = i - 1; j >= 0; j--)
        cout << hexaDeciNum[j];
}


int test_decToHexa_function()
{
    unsigned long value;
    //length of wannacry but in the prod release, the total value of our DLL will be uploaded
    value = 0x50D800; 
    printf("%lu\n", value);
    
    //we calculate the length of our DLL here but we need to convert it to hexadecimal and edit that value in the kernel shellcode
    //it is therefore imperative that we are able to convert decimal to hexadecimal for the purpose of shellcode generation
    int length = 5298176;
    decToHexa(length);
    //output = 50D800
    
    return 0;
}

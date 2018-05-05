/*************************************************************************
	> File Name: luhn.cpp
	> Author: 
	> Mail: 
	> Created Time: 六  5/ 5 10:34:30 2018
 ************************************************************************/

#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>
using namespace std;

/**
 * generate luhn check code
 */
int luhn_code(const string& card_no)
{
    int sum = 0;
    int odd = 1;
    for (auto it = card_no.rbegin(); it != card_no.rend(); ++it)
    {
        int digit = (*it) - '0';
        if (digit > 9 || digit < 0)
        {
            string err = card_no + " is not a digit";
            throw invalid_argument(err);
        }
        
        if (odd)
        {
            digit *= 2;
            if (digit > 10)
            {
                digit -= 9;
            }
        }

        sum += digit;

        odd^=1;
    }
    int next = (sum + 10) / 10 * 10;
    int code = next - sum;
    cout << "check code is: " << code << endl;
    return code;
}

bool luhn_check(const string& card_no)
{
    int sum = 0;
    int odd = 1;
    for (auto it = card_no.rbegin(); it != card_no.rend(); ++it)
    {
        int digit = (*it) - '0';
        if (digit > 9 || digit < 0)
        {
            string err = card_no + " is not a digit";
            throw invalid_argument(err);
        }

        if (!odd)
        {
            digit *= 2;
            if (digit > 10)
            {
                digit -= 9;
            }
        }

        sum += digit;

        odd^=1;
    }
    //cout << sum << endl;
    if (sum % 10 == 0)
    {
        return true;
    }
    else
    {
        return false;
    }

}

#ifdef MAIN_LUHN_CHECK
int main(int argc, char** argv)
{
    if (argc <= 1)
    {
        cerr << "Usage ./luhn_chek [number of credit card]!" << endl;
        return -1;
    }

    bool ret = luhn_check(argv[1]);
    cout << (ret ? "verify successfully" : "verify failed") << endl;

    
    return 0;
}
#endif

#ifdef MAIN_LUHN_CODE
int main(int argc, char** argv)
{
    if (argc <= 1)
    {
        cerr << "Usage ./luhn_code [number]!" << endl;
        return -1;
    }

    int code = luhn_code(argv[1]);
    return 0;
}

#endif

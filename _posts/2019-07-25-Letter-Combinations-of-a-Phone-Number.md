---
layout:     post
title:      LeetCode 17. Letter Combinations of a Phone Number
subtitle:   LintCode 425. Letter Combinations of a Phone Number
date:       2019-07-25
author:     Olivia Liu
header-img: img/post_img/dark-blue-high-tech-background-header.jpg
catalog: true
tags:
    - LintCode
    - LeetCode
    - DFS
    - English Version
    - C++
---
## Description
Given a digit string excluded `'0'` and `'1'`, return all possible letter combinations that the number could represent.

## Answer

The main idea of this problem is using depth-first-search to search for all the possible combinations. For each digit from input string, traverse all the possible letter which can be represented by the certain digit. When the size of subset equals to the size of the given digit string, push the subset into result. 

## Code

### C++

```c++
class Solution {
public:
    /**
     * @param digits: A digital string
     * @return: all posible letter combinations
     */
    // Using hash map to store the mapping of digits to letters:
    unordered_map<int, vector<string>> phone = {
        {2, {"a", "b", "c"}}, {3, {"d", "e", "f"}}, {4, {"g", "h", "i"}}, 
        {5, {"j", "k", "l"}}, {6, {"m", "n", "o"}}, {7, {"p", "q", "r", "s"}}, 
        {8, {"t", "u", "v"}}, {9, {"w", "x", "y", "z"}}
    };
    vector<string> letterCombinations(string &digits) {
        // write your code here
        vector<string> res;
        if(digits.length() == 0) return res;
        string s = "";
        helper(digits, 0, s, res);
        return res;
    }
    
    void helper(string &digits, int idx, string &s, vector<string> &res)
    {
        if(idx == digits.length())
        {
            res.push_back(s);
            return ;
        }
        for(int i = 0; i < phone[digits[idx] - '0'].size(); ++i)
        {
            s += phone[digits[idx] - '0'][i];
            helper(digits, idx + 1, s, res);
            s.erase(s.end() - 1);
        }
        return ;
    }
};
```


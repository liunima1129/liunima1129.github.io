---
layout:     post
title:      Leetcode Weekly Contest 162
subtitle:   Leetcode 周赛 162
date:       2019-11-09
author:     Olivia Liu
header-img: img/post_img/shahadat-shemul-7NgccS8ukSY-unsplash.jpg
catalog: true
tags:
    - LeetCode
    - C++
    - English Version
    - Contest

---

## Description

Total 4 questions:

**[Cells with Odd Values in a Matrix]( https://leetcode.com/contest/weekly-contest-162/problems/cells-with-odd-values-in-a-matrix/ )**

![162_1](img/post_img/contests_img/162_1.png)

**[Reconstruct a 2-Row Binary Matrix]( https://leetcode.com/contest/weekly-contest-162/problems/reconstruct-a-2-row-binary-matrix/ )**

![162_2](img/post_img/contests_img/162_2.png)

**[Number of Closed Islands]( https://leetcode.com/contest/weekly-contest-162/problems/number-of-closed-islands/ )**

![162_3](img/post_img/contests_img/162_3.png)

**[Maximum Score Words Formed by Letters]( https://leetcode.com/contest/weekly-contest-162/problems/maximum-score-words-formed-by-letters/ )**

![162_4](img/post_img/contests_img/162_4.png)

## Answer

### Cells with Odd Values in a Matrix

Traverse `indices` and modify the matrix at the same time. When modifies the matrix at each time, check if the cell is with an odd value or not. 

#### Time Complexity

 O(n<sup>2</sup>)

### Reconstruct a 2-Row Binary Matrix

If `colsum[i] == 2` then both the value of cells in i-th column are 1. Also, if `colsum[i] == 0` then both the value of cells in i-th column are 0. So to set the value of cells in columns whose `colsum` equals to 1, the main rule is to set the row with bigger gap to reach the total sum to 1.

#### Time Complexity 

O(n)

## Code

### C++

```c++
// Problem 1
class Solution {
public:
    int oddCells(int n, int m, vector<vector<int>>& indices) {
        if(n == 0 && m == 0) return 0;
        int len = indices.size();
        int res = 0;
        vector<vector<int>> mat(n, vector<int>(m, 0));
        for(int k = 0; k < len; ++k)
        {
            for(int i = 0; i < m; ++i)
            {
                mat[indices[k][0]][i]++;
                if(mat[indices[k][0]][i] % 2 == 1) res++;
                else res--;
            }
            for(int j = 0; j < n; ++j)
            {
                mat[j][indices[k][1]]++;
                if(mat[j][indices[k][1]] % 2 == 1) res++;
                else res--;
            }
        }
        return res;
    }
};

// Problem 2
class Solution {
public:
    vector<vector<int>> reconstructMatrix(int upper, int lower, vector<int>& colsum) {
        if(colsum.size() == 0) return {};
        int n = colsum.size();
        vector<vector<int>> res(2, vector<int>(n, 0));
        int up = 0, low = 0;
        for(int j = 0; j < n; ++j)
        {
            if(colsum[j] == 2)
            {
                res[0][j] = 1;
                res[1][j] = 1;
                up++;
                low++;
            }
            else if(colsum[j] == 0)
            {
                res[0][j] = 0;
                res[1][j] = 0;
            }
        }
        if(up == upper && low == lower) return res;
        if(up > upper || low > lower) return {};
        for(int j = 0; j < n; ++j)
        {
            if(colsum[j] != 1) continue;
            if(upper - up >= lower - low)
            {
                res[0][j] = 1;
                res[1][j] = 0;
                up++;
            }
            else 
            {
                res[0][j] = 0;
                res[1][j] = 1;
                low++;
            }
        }
        if(up != upper || low != lower) return {};
        return res;
    }
};
```
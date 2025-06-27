---
title: Prompt Engineering
published: 2025-06-27
description: '如何下有效的Prompt'
image: './images.jpg'
tags: [提示工程, LLM ,技巧]
category: 'Tech Sharing'
draft: false 
lang: ''
---

## Prompt Engineering

## RISEN
RISEN 架構提供了一種結構化的方式，可將複雜或受限的任務分解為可執行的步驟。它適用於研究報告、部落格文章或技術文件等結構化內容。它包含

角色- 定義 AI 的角色或專長。
指示- 清楚說明 AI 應該做什麼。
步驟- 概述逐步的方法。
終極目標- 明確指出期望的結果。
縮小範圍- 設定限制條件，以精簡焦點。

### 範本
```
Role: [Insert the role you want AI to take.]  

Main Task: [Insert the task you want AI to complete.]  

Steps to complete the task:  
1. [Step 1]  
2. [Step 2]  
3. [Step 3]  

Goal: [Define the goal of the output.]  

Constraints: [List any constraints, such as word limit, tone, or required sources.]
```

### 範例:

RISEN 最佳化提示：
```
角色：您是一名專業記者。

主要任務：總結所附文章。

完成任務的步驟：

找出關鍵論點和支持證據。
總結 5 個要點。
確保中立且專業的語氣。
目標：為一般讀者提供簡明的摘要。

限制：不超過 100 個字、不含個人意見。
```

## Recursive Criticism and Improvement (RCI) 技術

RCI 是一種以改進為基礎的提示技巧。這表示它是透過重複檢視、改進和精進答案的過程來運作，直到答案更好為止。

- 提示 LLM 分析和批判其目前的答案（例如："檢視您之前的答案，並找出答案中的問題」）。
- 接著，LLM 會依據所概述的批評，糾正已發現的問題，並相應地修改其輸出（例如：「根據您發現的問題，改善您的答案」）。

### 範例
步驟 1 - 初始提示：
寫一個 Python 函式來驗證電子郵件地址。

AI 回應：
```
import re

def is_valid_email(email):
    pattern = r"[^@]+@[^@]+\.[^@]+"
    return bool(re.match(pattern, email))
```
步驟 2 - 改良提示：
檢閱您之前的答案。找出潛在問題，並加以改善。

AI 回應：
```
from email_validator import validate_email, EmailNotValidError

def is_valid_email(email):
    if not isinstance(email, str):
        return False  # Ensure input is a string

    try:
        # Validate the email address using email-validator
        validate_email(email)
        return True
    except EmailNotValidError:
        return False
```
AI 增加了檢查功能以確保輸入為字串(if not isinstance(email, str))，並使用更可靠的email-validator函式庫取代正規表達式方法。這個函式庫提供符合 RFC 的電子郵件驗證，提供語法正確性和網域解析。結果是一個更健全的解決方案。

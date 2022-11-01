import re

regularExpression = '(^.$|^(.).*\\2$)'
pattern = re.compile(regularExpression)

query = int(input())
result = ['False'] * query

for i in range(query):
    someString = input()
    
    if pattern.match(someString):
        result[i] = 'True'

print(*result)
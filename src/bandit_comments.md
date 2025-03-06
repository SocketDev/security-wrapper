


  
<!--Socket External Tool Runner: Bandit -->  
  
**Possible SQL injection vector through string-based query construction.**  
**Severity**: `N/A`  
**Filename:** [code/socket-siem-connector/socketsync/connectors/bigquery.py](https://github.com/socketdev-demo/sast-testing/blob/61f7609dab5de1ff0214338e8a52b2c376a20258/code/socket-siem-connector/socketsync/connectors/bigquery.py#51)

```python
50         column_str = ", ".join(columns)
51         query = f"""
52         INSERT INTO `{self.table}` ({column_str}) VALUES 
53         """
54         for value in values:

```  

# mcp_tools/database.py

from typing import Dict, Any

def register_database_tools(mcp, hexstrike_client, logger):
    @mcp.tool()
    def mysql_query(
        host: str,
        user: str,
        password: str = "",
        database: str = "",
        query: str = ""
    ) -> Dict[str, Any]:
        """
        Query a MySQL database using the HexStrike server endpoint.

        Args:
            host: MySQL server address
            user: Username
            password: Password (optional)
            database: Database name
            query: SQL query

        Returns:
            Query results as JSON
        """
        data = {
            "host": host,
            "user": user,
            "password": password,
            "database": database,
            "query": query
        }
        try:
            return hexstrike_client.safe_post("api/tools/mysql", data)
        except Exception as e:
            logger.error(f"MySQL query failed: {e}")
            return {"error": str(e)}
        
    @mcp.tool()
    def sqlite_query(db_path: str, query: str) -> Dict[str, Any]:
        """
        Query a SQLite database using the HexStrike server endpoint.

        Args:
            db_path: Path to the SQLite database file
            query: SQL query to execute

        Returns:
            Query results as JSON

        Example:
            sqlite_query(
                db_path="/path/to/database.db",
                query="SELECT * FROM users;"
            )

        Usage:
            - Use for executing SELECT, INSERT, UPDATE, or DELETE statements on a local SQLite database file.
            - Returns JSON with query results or error details.
        """
        data = {
            "db_path": db_path,
            "query": query
        }
        try:
            return hexstrike_client.safe_post("api/tools/sqlite", data)
        except Exception as e:
            logger.error(f"SQLite query failed: {e}")
            return {"error": str(e)}
        
    @mcp.tool()
    def postgresql_query(host: str, user: str, password: str = "", database: str = "", query: str = "") -> Dict[str, Any]:
        """
        Query a PostgreSQL database using the HexStrike server endpoint.

        Args:
            host: PostgreSQL server address
            user: Username
            password: Password (optional)
            database: Database name
            query: SQL query to execute

        Returns:
            Query results as JSON

        Example:
            postgresql_query(
                host="localhost",
                user="admin",
                password="secret",
                database="mydb",
                query="SELECT * FROM employees;"
            )

        Usage:
            - Use for executing SQL statements on a remote or local PostgreSQL database.
            - Returns JSON with query results or error details.
        """
        data = {
            "host": host,
            "user": user,
            "password": password,
            "database": database,
            "query": query
        }
        try:
            return hexstrike_client.safe_post("api/tools/postgresql", data)    
        except Exception as e:
            logger.error(f"PostgreSQL query failed: {e}")
            return {"error": str(e)}

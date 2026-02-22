# mcp_tools/db_query/postgresql.py

from typing import Dict, Any

def register_postgresql_tools(mcp, hexstrike_client, logger):
    
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

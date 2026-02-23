# mcp_tools/db_query/mysql.py

from typing import Any, Dict

def register_mysql_tools(mcp, hexstrike_client, logger):
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
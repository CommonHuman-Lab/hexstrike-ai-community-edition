# mcp_tools/db_query/sqlite.py

from typing import Any, Dict

def register_sqlite_tools(mcp, hexstrike_client, logger):
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
    
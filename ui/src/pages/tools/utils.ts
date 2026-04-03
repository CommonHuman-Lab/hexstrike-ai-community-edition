import type { Tool } from '../../api'

export function getToolCategories(tools: Tool[]): string[] {
  return ['all', ...Array.from(new Set(tools.map(tool => tool.category))).sort()]
}

export function filterTools(
  tools: Tool[],
  toolsStatus: Record<string, boolean>,
  activeCategory: string,
  search: string,
  missingOnly: boolean
): Tool[] {
  const query = search.toLowerCase()

  return tools
    .filter(tool => {
      const matchCategory = activeCategory === 'all' || tool.category === activeCategory
      const matchSearch = !query
        || tool.name.includes(query)
        || tool.desc.toLowerCase().includes(query)
        || tool.parent_tool?.includes(query)
        || tool.parent_tool?.toLowerCase().includes(query)
      const matchMissing = !missingOnly || toolsStatus[tool.name] === false
      return matchCategory && matchSearch && matchMissing
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

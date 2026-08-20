import type { PayloadWorkbenchOperation } from '../../api'
import type { RecipeStep } from './RecipePanel'

interface RecipeFileEntry {
  operation_id: string
  params?: Record<string, string>
}

export function downloadRecipeAsFile(recipe: RecipeStep[]): void {
  const entries: RecipeFileEntry[] = recipe.map(s => ({ operation_id: s.operationId, params: s.params }))
  const blob = new Blob([JSON.stringify(entries, null, 2)], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'payload-workbench-recipe.json'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export function parseRecipeFile(
  json: string,
  operations: PayloadWorkbenchOperation[]
): { steps: RecipeStep[]; skipped: number } {
  const entries = JSON.parse(json) as RecipeFileEntry[]
  if (!Array.isArray(entries)) throw new Error('Expected a JSON array of recipe steps.')

  let skipped = 0
  const steps = entries
    .map((entry): RecipeStep | null => {
      const operation = operations.find(op => op.id === entry.operation_id)
      if (!operation) {
        skipped++
        return null
      }
      return {
        stepId: crypto.randomUUID(),
        operationId: entry.operation_id,
        operationName: operation.name,
        params: entry.params ?? {},
      }
    })
    .filter((s): s is RecipeStep => s !== null)

  return { steps, skipped }
}

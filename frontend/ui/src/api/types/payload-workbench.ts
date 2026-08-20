export interface PayloadWorkbenchParamSpec {
  name: string;
  label: string;
  type: 'text' | 'textarea' | 'number' | 'select';
  required: boolean;
  default: string | number;
  help_text: string;
  choices?: string[];
  hidden?: boolean;
}

export interface PayloadWorkbenchOperation {
  id: string;
  category: string;
  name: string;
  description: string;
  params: PayloadWorkbenchParamSpec[];
}

export interface PayloadWorkbenchOperationsResponse {
  success: boolean;
  categories: string[];
  operations: PayloadWorkbenchOperation[];
}

export interface PayloadWorkbenchRunResponse {
  success: boolean;
  output?: string;
  output_mime?: string;
  note?: string;
  error?: string;
}

export interface PayloadWorkbenchRecipeStepInput {
  operation_id: string;
  params: Record<string, unknown>;
}

export interface PayloadWorkbenchRecipeStepResult {
  operation_id: string;
  name?: string;
  input?: string;
  output?: string;
  output_mime?: string;
  error?: string;
}

export interface PayloadWorkbenchRunRecipeOptions {
  continueOnError?: boolean;
  stopAfterStepIndex?: number;
  stepInputOverrides?: Record<number, string>;
}

export interface PayloadWorkbenchRunRecipeResponse {
  success: boolean;
  output?: string;
  output_mime?: string;
  has_errors?: boolean;
  steps?: PayloadWorkbenchRecipeStepResult[];
  error?: string;
}

export interface PayloadWorkbenchSavedRecipe {
  recipe_id: string;
  name: string;
  steps: PayloadWorkbenchRecipeStepInput[];
  created_at: string;
  updated_at: string;
}

export interface PayloadWorkbenchRecipesResponse {
  success: boolean;
  recipes: PayloadWorkbenchSavedRecipe[];
  error?: string;
}

export interface PayloadWorkbenchRecipeMutationResponse {
  success: boolean;
  recipe?: PayloadWorkbenchSavedRecipe;
  error?: string;
}

export interface PayloadWorkbenchRecipeDeleteResponse {
  success: boolean;
  error?: string;
}

export interface TestPayloadAgainstTargetResponse {
  success: boolean;
  ai_analysis?: {
    payload_tested: string;
    target_url: string;
    method: string;
    response_size: number;
    success: boolean;
    potential_vulnerability: boolean;
    recommendations: string[];
  };
  error?: string;
}

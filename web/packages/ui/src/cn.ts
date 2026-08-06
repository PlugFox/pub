import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merges class lists: clsx handles conditionals/arrays, tailwind-merge
 * resolves conflicting Tailwind utilities (the last one wins). Every component
 * must funnel its `class` prop through this.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

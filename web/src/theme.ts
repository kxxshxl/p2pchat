import { useEffect, useState } from "react";

export type ThemeChoice = "system" | "light" | "dark";
const KEY = "parley-theme";

function read(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

export function applyTheme(choice: ThemeChoice = read()): void {
  if (choice === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = choice;
}

export function useTheme(): [ThemeChoice, (choice: ThemeChoice) => void] {
  const [theme, setTheme] = useState<ThemeChoice>(read);
  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* private mode */
    }
  }, [theme]);
  return [theme, setTheme];
}

import { useCallback, useEffect, useState } from "react";

/**
 * Light or dark, as a browser-local preference.
 *
 * Stored in `localStorage` rather than on the server, for the same reason the
 * dismissed-warning flag is: it says how this person likes to look at the
 * console, not anything about the server being reviewed, and it must never
 * travel with a configuration. A browser that refuses storage still toggles —
 * the choice simply does not survive the reload, which is the harmless way for
 * this to fail.
 *
 * The palette itself lives entirely in `styles.css`, hanging off
 * `html[data-theme]`. Nothing here knows a colour.
 */
export type Theme = "light" | "dark";

const KEY = "hmcp.theme";
const QUERY = "(prefers-color-scheme: dark)";

function stored(): Theme | null {
  try {
    const value = localStorage.getItem(KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

function system(): Theme {
  try {
    return matchMedia(QUERY).matches ? "dark" : "light";
  } catch {
    return "light";
  }
}

const apply = (theme: Theme) => {
  document.documentElement.dataset["theme"] = theme;
};

/**
 * Called from the entry module, before the first render.
 *
 * The console's CSP is `script-src 'self'`, so there is no inline script to set
 * the attribute in `<head>` — the usual way to beat the flash. This runs during
 * module evaluation instead, which is still ahead of React's first paint but
 * behind the stylesheet's. The media query in `styles.css` covers that gap for
 * the canvas, which is the only part of it anyone can see.
 */
export function initTheme(): Theme {
  const theme = stored() ?? system();
  apply(theme);
  return theme;
}

export function useTheme(): { theme: Theme; toggle: () => void; following: boolean } {
  const [theme, setTheme] = useState<Theme>(() => stored() ?? system());
  const [following, setFollowing] = useState(() => stored() === null);

  useEffect(() => apply(theme), [theme]);

  /*
   * While no explicit choice has been made, the console follows the OS — so a
   * machine that switches at sunset takes the console with it rather than
   * stranding it in the palette it happened to load in. The first toggle ends
   * that, because at that point the reader has said what they want.
   */
  useEffect(() => {
    if (!following) return;
    let media: MediaQueryList;
    try {
      media = matchMedia(QUERY);
    } catch {
      return;
    }
    const onChange = (e: MediaQueryListEvent) => setTheme(e.matches ? "dark" : "light");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [following]);

  const toggle = useCallback(() => {
    setTheme((current) => {
      const next: Theme = current === "dark" ? "light" : "dark";
      try {
        localStorage.setItem(KEY, next);
      } catch {
        /* a session without storage toggles for as long as it lasts */
      }
      return next;
    });
    setFollowing(false);
  }, []);

  return { theme, toggle, following };
}

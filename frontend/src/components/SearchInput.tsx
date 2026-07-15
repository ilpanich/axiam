import { useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";
import { cn } from "@/lib/utils";

interface SearchInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
  /**
   * Accessible name for the field. Falls back to `placeholder` for backwards
   * compatibility, but prefer an explicit label so the control still has a
   * name once the user types (a placeholder disappears) or if `placeholder`
   * is empty.
   */
  label?: string;
}

/**
 * Debounced search input — calls onChange 300ms after the user stops typing.
 * Manages its own internal state so the input feels instant.
 */
export function SearchInput({
  value,
  onChange,
  placeholder = "Search…",
  className,
  label,
}: SearchInputProps) {
  const [local, setLocal] = useState(value);
  const [prevValue, setPrevValue] = useState(value);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sync external value → local (e.g. on reset) by adjusting state during
  // render when the incoming prop changes, rather than in an effect.
  if (value !== prevValue) {
    setPrevValue(value);
    setLocal(value);
  }

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    const next = e.target.value;
    setLocal(next);

    if (timerRef.current !== null) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      onChange(next);
    }, 300);
  }

  // Clean up on unmount
  useEffect(() => {
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current);
    };
  }, []);

  return (
    <div className={cn("relative", className)}>
      <Search
        size={15}
        className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
        aria-hidden="true"
      />
      <input
        type="search"
        value={local}
        onChange={handleChange}
        placeholder={placeholder}
        aria-label={label ?? placeholder}
        className={cn(
          "focus-ring h-9 w-full rounded-md pl-9 pr-3 text-sm",
          "bg-white/5 border border-primary/20 text-foreground",
          "placeholder:text-muted-foreground",
          "focus:border-primary",
          "transition-colors duration-200"
        )}
      />
    </div>
  );
}

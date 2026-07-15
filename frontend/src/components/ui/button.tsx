import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all duration-200 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        // `active:` states give touch users press feedback since `hover:`
        // variants only fire on hover-capable pointers (Tailwind gates the
        // hover variant behind `@media (hover: hover)`).
        default:
          "bg-primary text-primary-foreground hover:shadow-glow-cyan hover:-translate-y-0.5 active:shadow-glow-cyan",
        destructive:
          "bg-destructive text-destructive-foreground hover:opacity-90 active:opacity-90",
        outline:
          "border border-primary/30 bg-transparent text-primary hover:bg-primary/10 hover:border-primary hover:shadow-glow-cyan active:bg-primary/10",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80 active:bg-secondary/80",
        ghost:
          "text-muted-foreground hover:bg-white/5 hover:text-foreground active:bg-white/5",
        link: "text-primary underline-offset-4 hover:underline active:underline",
        accent:
          "bg-accent text-accent-foreground hover:shadow-glow-purple hover:-translate-y-0.5 active:shadow-glow-purple",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-11 rounded-md px-8",
        icon: "h-10 w-10",
        // 44px — comfortable touch target for tablet/touch contexts.
        "icon-touch": "h-11 w-11",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = ({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: ButtonProps) => {
  const Comp = asChild ? Slot : "button";
  return (
    <Comp
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  );
};

Button.displayName = "Button";

// eslint-disable-next-line react-refresh/only-export-components
export { Button, buttonVariants };

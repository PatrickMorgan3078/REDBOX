import { Oxanium } from "next/font/google";
import "./globals.css";

const oxanium = Oxanium({
  subsets: ['latin'],
  weight: ['400', '700'], // You can add more like '300', '500' if needed
  variable: '--font-oxanium',
});

export const metadata = {
  title: "Red Box",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={oxanium.variable}>
      <body>{children}</body>
    </html>
  );
}

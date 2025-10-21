"use client"; // make the entire page client-side

import VaultLayout from "@/app/components/VaultLayout";
import { useParams } from "next/navigation";

export default function VaultPage() {
  const { id } = useParams(); // this is now safe because it's client-side

  return <VaultLayout vaultName={id} />;
}

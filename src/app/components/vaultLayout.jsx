"use client";

import { useRef, useState, useEffect } from "react";
import PocketBase from "pocketbase";

// --------------------- CRYPTOGRAPHY UTILITIES (Web Crypto API) ---------------------
// Text Encoder for key derivation
const enc = new TextEncoder();

// Helper to convert ArrayBuffer to Base64 string for DB storage
function toBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))); 
}

// Key Derivation Function (PBKDF2) - Derives a secure key from a passphrase
async function deriveKey(passphrase, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", 
    enc.encode(passphrase), 
    { name: "PBKDF2" }, 
    false, 
    ["deriveKey"]
  ); 
  
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, 
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"] 
  );
}

export default function VaultLayout({ children, vaultName }) {
  const vaultDisplayName = vaultName || "Vault";
  const fileInputRef = useRef(null);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalMessage, setModalMessage] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [showVaultSecurityModal, setShowVaultSecurityModal] = useState(false);

  const pb = new PocketBase("http://127.0.0.1:8090");

  const [user, setUser] = useState(pb.authStore.model);

  useEffect(() => {
    setUser(pb.authStore.model);
    const unsubscribe = pb.authStore.onChange(() => {
      setUser(pb.authStore.model);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const fetchFiles = async () => {
      if (!user?.id) return;

      try {
        const existingFiles = await pb.collection("file_info").getFullList({
          filter: `owner="${user.id}"`,
        });

        const mappedFiles = existingFiles.map(f => ({
          id: f.id,
          collectionId: f.collectionId,
          file_name: f.file_name,
          file_type: f.file_type,
          uploaded: true,
          stored_file_name: f.file,
          is_encrypted: f.is_encrypted || false,
          salt: f.salt || "",
          iv: f.iv || "",
          url: f.file_type.startsWith("image/")
            ? `${pb.baseUrl}/api/files/${f.collectionId}/${f.id}/file/${f.file}`
            : null,
        }));

        setFiles(mappedFiles);
      } catch (err) {
        console.error("Failed to fetch files:", err);
        setModalMessage("Failed to load files. Check console.");
      }
    };

    fetchFiles();
  }, [user?.id]);

  const handleFileChange = (event) => {
    const selectedFiles = Array.from(event.target.files).map(f => ({
      file: f,
      uploaded: false,
      file_name: f.name,
      file_type: f.type,
    }));
    setFiles(prev => [...prev, ...selectedFiles]);
  };

  const handleUpload = async () => {
    if (!user?.id) {
      setModalMessage("You must be logged in to upload files.");
      return;
    }

    setLoading(true);

    try {
      const updatedFiles = [...files];

      for (let i = 0; i < updatedFiles.length; i++) {
        const file = updatedFiles[i];
        if (file.uploaded) continue;

        const formData = new FormData();
        formData.append("file_name", file.file_name || "Unnamed File");
        formData.append("file_type", file.file_type || "unknown");
        formData.append("is_encrypted", false); 
        formData.append("salt", "");
        formData.append("iv", "");
        formData.append("encryption_id", "N/A"); 
        formData.append("encryption_key", "N/A");
        formData.append("file", file.file);
        formData.append("owner", user.id);

        const createdFile = await pb.collection("file_info").create(formData);

        updatedFiles[i] = {
          ...file,
          uploaded: true,
          id: createdFile.id,
          collectionId: createdFile.collectionId,
          stored_file_name: createdFile.file,
          is_encrypted: false,
          url: file.file_type.startsWith("image/")
            ? `${pb.baseUrl}/api/files/${createdFile.collectionId}/${createdFile.id}/${createdFile.file_name}`
            : null,
        };
      }

      setFiles(updatedFiles);
      setModalMessage("✅ Files successfully added to storage!");
    } catch (err) {
      console.error("Upload error:", err);
      setModalMessage("Upload failed. Check console.");
    } finally {
      setLoading(false);
    }
  };

  // --------------------- ENCRYPTION LOGIC ---------------------
  const handleEncrypt = async (file) => {
    if (!file || file.is_encrypted) {
      setModalMessage("File is already encrypted.");
      return;
    }

    const passphrase = prompt("Enter a strong passphrase to encrypt this file:");
    if (!passphrase) return;

    setModalMessage(`Encrypting file: ${file.file_name}...`);

    try {
      const fileUrl = `${pb.baseUrl}/api/files/${file.collectionId}/${file.id}/${file.stored_file_name}`;
      const response = await fetch(fileUrl);
      if (!response.ok) throw new Error("Failed to fetch file for encryption.");
      
      const fileBuf = await response.arrayBuffer(); 
      
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      
      const key = await deriveKey(passphrase, salt);
      
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        fileBuf
      );
      
      const encryptedBlob = new Blob([ciphertext], { type: "application/octet-stream" });
      const encryptedFile = new File([encryptedBlob], `${file.file_name}.enc`, { type: "application/octet-stream" });
      
      const formData = new FormData();
      formData.append("file", encryptedFile); 
      formData.append("is_encrypted", true);
      formData.append("salt", toBase64(salt)); 
      formData.append("iv", toBase64(iv)); 
      
      const updatedRecord = await pb.collection("file_info").update(file.id, formData);
      
      setModalMessage(`✅ File '${file.file_name}' successfully encrypted!`);
      
      setFiles(prev => prev.map(f => 
        f.id === file.id 
        ? { 
            ...f, 
            is_encrypted: true, 
            salt: updatedRecord.salt,
            iv: updatedRecord.iv,
            stored_file_name: updatedRecord.file,
            file_name: `${f.file_name} (Encrypted)`,
          }
        : f
      ));
      
    } catch (error) {
      console.error("Encryption failed:", error);
      setModalMessage("❌ Encryption failed. Check console.");
    }
  };

  return (
    <div style={styles.page}>
      <header style={styles.topbar}>
        <div style={styles.vaultName}>{vaultDisplayName}</div>
        <button style={styles.profileBtn}>Profile</button>
      </header>

      <section style={styles.bigSlot}>
        <div
          style={styles.fileGrid}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              fileInputRef.current?.click();
            }
          }}
        >
          {files.length === 0 ? (
            <div style={styles.uploadContent}>
              <div style={styles.arrow}>↑</div>
              <div style={styles.uploadText}>Click to Add Files</div>
            </div>
          ) : (
            files.map((file) => (
              <div
                key={file.id}
                style={styles.fileCard}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedFile(file);
                }}
              >
                {file.file_type?.startsWith("image/") ? (
                  <img
                    src={file.uploaded ? file.url : URL.createObjectURL(file.file)}
                    alt={file.file_name}
                    style={styles.filePreview}
                  />
                ) : (
                  <div style={styles.fileIcon}>📄</div>
                )}
                <div style={styles.fileName}>{file.file_name}</div>
              </div>
            ))
          )}
        </div>

        <input
          type="file"
          ref={fileInputRef}
          style={{ display: "none" }}
          onChange={handleFileChange}
          multiple
        />
      </section>

      {files.length > 0 && (
        <div style={styles.uploadBtnWrapper}>
          <button style={styles.uploadBtn} onClick={handleUpload} disabled={loading}>
            {loading ? "Uploading..." : "Add Files to Storage"}
          </button>
        </div>
      )}

      <main style={styles.main}>{children}</main>

      {selectedFile && (
        <div
          style={styles.fileModalOverlay}
          onClick={() => setSelectedFile(null)}
        >
          <div
            style={styles.fileModalContent}
            onClick={(e) => e.stopPropagation()}
          >
            {selectedFile.file_type?.startsWith("image/") ? (
              <img
                src={selectedFile.url}
                alt={selectedFile.file_name}
                style={styles.modalImage}
              />
            ) : (
              <div style={styles.modalFileIcon}>📄</div>
            )}
            <div style={styles.modalFileName}>{selectedFile.file_name}</div>
          </div>

          {/* Floating Buttons */}
          <button
            style={{ ...styles.modalBtn, left: "40px" }}
            onClick={() => handleEncrypt(selectedFile)}
          >
            {selectedFile?.is_encrypted ? "Encrypted" : "Encrypt"}
          </button>
          <button
            style={{ ...styles.modalBtn, right: "40px" }}
            onClick={async () => {
              if (!selectedFile?.id) return;

              // NEW: Prevent download if file is encrypted
              if (selectedFile?.is_encrypted) {
                setModalMessage(
                  `❌ The file '${selectedFile.file_name}' is encrypted and cannot be downloaded.`
                );
                return;
              }

              try {
                // CORRECT DOWNLOAD URL (using collection ID and stored file name)
                const fileUrl = `${pb.baseUrl}/api/files/${selectedFile.collectionId}/${selectedFile.id}/${encodeURIComponent(selectedFile.stored_file_name)}?download=1`;

                const a = document.createElement("a");
                a.href = fileUrl;
                a.download = selectedFile.file_name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
              } catch (error) {
                console.error("Download failed:", error);
                setModalMessage("❌ Download failed. Please try again.");
              }
            }}
          >
            Download
          </button>
        </div>
      )}

      {modalMessage && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            backgroundColor: "rgba(0,0,0,0.75)",
            backdropFilter: "blur(5px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 99999,
          }}
          onClick={() => setModalMessage("")} // dismiss when clicking outside
        >
          <div
            style={{
              background: "#1a1a1a",
              padding: "24px 32px",
              borderRadius: "12px",
              boxShadow: "0 0 20px rgba(229,9,20,0.5)",
              maxWidth: "90%",
              textAlign: "center",
              color: "white",
            }}
            onClick={(e) => e.stopPropagation()} // prevent closing when clicking inside
          >
            <p style={{ marginBottom: "20px", fontSize: "16px" }}>{modalMessage}</p>
            <button
              style={{
                padding: "10px 20px",
                borderRadius: "999px",
                border: "none",
                background: "#e50914",
                color: "white",
                fontWeight: "600",
                cursor: "pointer",
                boxShadow: "0 0 10px rgba(229,9,20,0.4)",
              }}
              onClick={() => setModalMessage("")}
            >
              OK
            </button>
          </div>
        </div>
      )}

      {/* Add Vault Security Button (Right-Bottom Corner) */}
      <button
        style={styles.addVaultBtn}
        onClick={() => setShowVaultSecurityModal(true)}
      >
        Add Vault Security
      </button>

      {/* Vault Security Modal */}
      {showVaultSecurityModal && (
        <div
          style={styles.modalOverlay}
          onClick={() => setShowVaultSecurityModal(false)}
        >
          <div style={styles.vaultModal} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ color: "#e50914", marginBottom: "20px" }}>Vault Security Options</h3>
            <button style={styles.vaultOptionBtn} onClick={() => alert("Password Security selected")}>
              Password Security
            </button>
            <button style={styles.vaultOptionBtn} onClick={() => alert("Location/Time Trigger selected")}>
              Location/Time Trigger
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// --------------------- Styles ---------------------
const styles = {
  page: { minHeight: "100vh", background: "black", color: "white", display: "flex", justifyContent: "center", flexDirection: "column", padding: "24px", boxSizing: "border-box" },
  topbar: { width: "100%", maxWidth: "1800px", display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "32px", paddingLeft: "24px", paddingRight: "0px", margin: "0 auto", boxSizing: "border-box" },
  vaultName: { fontFamily: "'Orbitron', sans-serif", fontSize: "28px", fontWeight: "bold", color: "#e50914", letterSpacing: "0.5px" },
  profileBtn: { fontSize: "14px", padding: "8px 12px", background: "#1a1a1a", border: "1px solid rgba(229,9,20,0.45)", borderRadius: "999px", color: "white", cursor: "pointer", boxShadow: "0 0 10px rgba(229,9,20,0.25)" },
  bigSlot: { width: "100%", maxWidth: "1500px", minHeight: "300px", flex: 1, background: "#1a1a1a", border: "1px solid rgba(229,9,20,0.45)", borderRadius: "12px", padding: "20px", margin: "0 auto 32px", boxShadow: "0 0 14px rgba(229,9,20,0.25)", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", cursor: "crosshair", transition: "all 0.2s ease" },
  uploadContent: { textAlign: "center" },
  arrow: { fontSize: "48px", color: "#e50914", marginBottom: "12px" },
  uploadText: { fontSize: "18px", fontWeight: "600", color: "#ccc" },
  fileGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(120px, 1fr))", gap: "16px", width: "100%" },
  fileCard: { background: "#2a2a2a", borderRadius: "8px", padding: "10px", textAlign: "center", color: "white", fontSize: "14px", wordBreak: "break-word", cursor: "zoom-in" },
  filePreview: { width: "100%", height: "100px", objectFit: "cover", borderRadius: "6px", marginBottom: "8px" },
  fileIcon: { fontSize: "40px", marginBottom: "8px" },
  fileName: { fontSize: "12px", color: "#ccc" },
  uploadBtnWrapper: { display: "flex", justifyContent: "center", marginBottom: "24px" },
  uploadBtn: { padding: "12px 20px", background: "#e50914", border: "none", borderRadius: "999px", color: "white", fontSize: "16px", fontWeight: "600", cursor: "pointer", boxShadow: "0 0 10px rgba(229,9,20,0.4)" },
  fileModalOverlay: { position: "fixed", top: 0, left: 0, width: "100vw", height: "100vh", backgroundColor: "rgba(0,0,0,0.7)", backdropFilter: "blur(6px)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999 },
  fileModalContent: { position: "relative", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", background: "#1a1a1a", borderRadius: "12px", padding: "20px", maxWidth: "80%", maxHeight: "80%", overflow: "hidden" },
  modalImage: { maxWidth: "100%", maxHeight: "400px", marginBottom: "16px", borderRadius: "8px" },
  modalFileIcon: { fontSize: "80px", marginBottom: "16px" },
  modalFileName: { fontSize: "18px", color: "#ccc", marginBottom: "24px" },
  modalBtn: { position: "fixed", top: "50%", transform: "translateY(-50%)", padding: "12px 20px", background: "#e50914", border: "none", borderRadius: "999px", color: "white", cursor: "pointer", fontWeight: "600", zIndex: 10000 }, addVaultBtn: {position: "absolute", bottom: "20px", right:"20px",padding: "10px 16px", background: "#e50914", border: "none", borderRadius: "999px", color: "white",fontWeight: "600", cursor: "pointer", boxShadow: "0 0 10px rgba(229,9,20,0.4)", zIndex: 5000,},vaultModal: {background: "#1a1a1a", padding: "24px", borderRadius: "12px", display: "flex",flexDirection: "column", alignItems: "center", gap: "16px",} , vaultOptionBtn: {padding: "12px 20px",background: "#e50914", border: "none", borderRadius: "999px", color: "white", fontWeight: "600",cursor: "pointer", width: "220px",}, 
};

'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation'; 
import PocketBase from 'pocketbase';

const pb = new PocketBase('http://127.0.0.1:8090'); // PocketBase server URL

export default function AuthPage() {
  const router = useRouter(); 
  const [isRegistering, setIsRegistering] = useState(false);
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [securityQuestion, setSecurityQuestion] = useState('');
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [notification, setNotification] = useState(''); // notification message

  const showNotification = (msg) => {
    setNotification(msg);
    setTimeout(() => setNotification(''), 3000); // disappears after 3 seconds
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Validate fields
    if (!email || !password || !securityQuestion || !securityAnswer || (isRegistering && (!firstName || !lastName))) {
      showNotification('Please fill all required fields');
      return;
    }

    try {
      if (isRegistering) {
        // Register user in default 'users' collection
        await pb.collection('users').create({
          email,
          password,
          passwordConfirm: password,
          first_name: firstName,
          last_name: lastName,
          security_question: securityQuestion,
          security_answer: securityAnswer,
        });
        showNotification('Registration successful!');
      } else {
        // Login using default PocketBase auth
        await pb.collection('users').authWithPassword(email, password);

        const user = pb.authStore.model;
        if (user.security_answer !== securityAnswer) {
          pb.authStore.clear();
          showNotification('Incorrect security answer!');
          return;
        }

        showNotification('Login successful!');
        setTimeout(() => {
          router.push('/vaults');
        }, 1000);
      }
    } catch (err) {
      console.error(err);
      showNotification('Error: ' + (err.message || JSON.stringify(err)));
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>{isRegistering ? 'Register' : 'Login'} to RedBox</h1>

        {notification && <div style={styles.notification}>{notification}</div>}

        <form onSubmit={handleSubmit} style={styles.form}>
          {isRegistering && (
            <>
              <input
                type="text"
                placeholder="First Name"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                style={styles.input}
              />
              <input
                type="text"
                placeholder="Last Name"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                style={styles.input}
              />
            </>
          )}

          <input
            type="email"
            placeholder="Email Address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={styles.input}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={styles.input}
          />

          <select
            value={securityQuestion}
            onChange={(e) => setSecurityQuestion(e.target.value)}
            style={{ ...styles.input, color: 'grey' }}
          >
            <option value="" disabled hidden>
              Select Security Question
            </option>
            <option value="first_pet">What was your first pet's name?</option>
            <option value="nickname">What is your childhood nickname?</option>
            <option value="school">What was the name of your first school?</option>
            <option value="hero">Who was your childhood hero?</option>
          </select>

          <input
            type="text"
            placeholder="Answer to Security Question"
            value={securityAnswer}
            onChange={(e) => setSecurityAnswer(e.target.value)}
            style={styles.input}
          />

          <button type="submit" style={styles.button}>
            {isRegistering ? 'Create Account' : 'Login'}
          </button>
        </form>

        <p style={styles.switchText}>
          {isRegistering ? 'Already have an account?' : "Don't have an account?"}{' '}
          <span onClick={() => setIsRegistering(!isRegistering)} style={styles.link}>
            {isRegistering ? 'Login' : 'Register'}
          </span>
        </p>
      </div>
    </div>
  );
}

const styles = {
  container: { minHeight: '100vh', backgroundColor: 'black', color: 'white', display: 'flex', justifyContent: 'center', alignItems: 'center' },
  card: { background: '#1a1a1a', padding: '40px', borderRadius: '12px', width: '100%', maxWidth: '400px', boxShadow: '0 0 20px rgba(255,0,0,0.3)' },
  title: { fontSize: '28px', marginBottom: '20px', fontWeight: 'bold', textAlign: 'center', fontFamily: "'Orbitron', sans-serif" },
  form: { display: 'flex', flexDirection: 'column', gap: '16px' },
  input: { padding: '12px', borderRadius: '6px', border: 'none', fontSize: '16px' },
  button: { padding: '12px', borderRadius: '6px', backgroundColor: '#e50914', border: 'none', fontWeight: 'bold', color: 'white', fontSize: '16px', cursor: 'pointer' },
  switchText: { marginTop: '20px', textAlign: 'center', fontSize: '14px' },
  link: { color: '#e50914', cursor: 'pointer', textDecoration: 'underline', marginLeft: '4px' },
  notification: {
    backgroundColor: '#333',
    color: '#e50914',
    padding: '10px 16px',
    borderRadius: '8px',
    textAlign: 'center',
    marginBottom: '16px',
    fontWeight: 'bold',
    boxShadow: '0 0 10px rgba(255,0,0,0.5)',
    fontFamily: "'Orbitron', sans-serif",
  },
};

'use client';
import login from './auth/page'
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AnimatePresence, motion } from 'framer-motion';
import Lottie from 'lottie-react';
import lockAnimation from '../../public/lock-animation.json';

export default function Home() {
  const [showFade, setShowFade] = useState(false);
  const [showTitle, setShowTitle] = useState(false);
  const [showButton, setShowButton] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const fadeTimer = setTimeout(() => setShowFade(true), 2000);
    const titleTimer = setTimeout(() => setShowTitle(true), 3000);
    const buttonTimer = setTimeout(() => setShowButton(true), 4200);

    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(titleTimer);
      clearTimeout(buttonTimer);
    };
  }, []);

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-white">
      {/* Lock Animation */}
      <div className="absolute inset-0 flex items-center justify-center z-10">
        <Lottie
          animationData={lockAnimation}
          loop={false}
          autoplay
          className="w-44 h-44"
        />
      </div>

      {/* Black Fade In */}
      <AnimatePresence>
        {showFade && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8 }}
            className="absolute inset-0 bg-black z-20"
          />
        )}
      </AnimatePresence>

      {/* Red Box Title (slides up slightly) */}
      <AnimatePresence>
        {showTitle && (
          <motion.h1
            initial={{ opacity: 0, scale: 0.8, y: 0 }}
            animate={{ opacity: 1, scale: 1, y: -60 }}
            transition={{ duration: 0.8 }}
            className="absolute top-1/2 left-1/2 text-white text-8xl -translate-x-1/2 -translate-y-1/2 z-30 [font-family:'Helvetica',sans-serif]"
          >
            RED BOX
          </motion.h1>
        )}
      </AnimatePresence>

      
      <AnimatePresence>
        {showButton && (
          <motion.button
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="absolute top-[60%] left-1/2 -translate-x-1/2 bg-white text-black font-semibold px-6 py-3 rounded-full z-30 hover:bg-gray-200 transition"
            onClick={() => router.push('/auth')}
          >
            Get Started
          </motion.button>
        )}
      </AnimatePresence>
    </div>
  );
}

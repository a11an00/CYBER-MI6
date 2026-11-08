import { writable } from 'svelte/store';
import type { UserProfile } from '../types/auth';

function createAuth() {
  const { subscribe, set } = writable({
    isAuthenticated: false,
    initialized: false,
    user: null as UserProfile | null,
    token: null as string | null
  });

  return {
    subscribe,
    login: (newToken: string, profile: UserProfile) => {
      localStorage.setItem('cyber_mi6_token', newToken);
      localStorage.setItem('cyber_mi6_user', JSON.stringify(profile));
      set({ isAuthenticated: true, initialized: true, user: profile, token: newToken });
    },
    logout: () => {
      localStorage.removeItem('cyber_mi6_token');
      localStorage.removeItem('cyber_mi6_user');
      set({ isAuthenticated: false, initialized: true, user: null, token: null });
      window.location.hash = '#/'; 
    },
    init: () => {
      const savedToken = localStorage.getItem('cyber_mi6_token');
      const savedUser = localStorage.getItem('cyber_mi6_user');
      
      if (savedToken && savedUser) {
        try {
          const profile = JSON.parse(savedUser);
          set({ isAuthenticated: true, initialized: true, user: profile, token: savedToken });
        } catch (e) {
          localStorage.removeItem('cyber_mi6_token');
          localStorage.removeItem('cyber_mi6_user');
          set({ isAuthenticated: false, initialized: true, user: null, token: null });
        }
      } else {
        // No saved session — still mark as initialized so the login screen renders.
        set({ isAuthenticated: false, initialized: true, user: null, token: null });
      }
    }
  };
}

export const auth = createAuth();

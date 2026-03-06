import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = "https://saecwjmbowqxkgeznyjb.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_XuzTy21DGcMJCFpjcMIXrg_MetI0Pac";

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

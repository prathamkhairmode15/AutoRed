import { useState } from 'react';
import { supabase } from '../../lib/supabaseClient';

export default function LoginPage() {
    const [userId, setUserId] = useState('');
    const [otp, setOtp] = useState('');
    const [otpRequested, setOtpRequested] = useState(false);
    const [status, setStatus] = useState({ msg: '', type: '' });
    const [loading, setLoading] = useState(false);

    const clearErrors = () => {
        setStatus({ msg: '', type: '' });
    };

    const handleGetOtp = async (e) => {
        if (e) e.preventDefault();
        clearErrors();

        if (!userId) {
            setStatus({ msg: '// USER ID REQUIRED', type: 'error' });
            return;
        }

        setLoading(true);
        setStatus({ msg: '// LOOKING UP ACCOUNT...', type: '' });

        try {
            // 1) Find email for this userId in Supabase
            const { data, error } = await supabase
                .from("app_users")
                .select("email")
                .eq("user_id", userId)
                .single();

            if (error || !data) {
                setStatus({ msg: '// UNKNOWN USER ID', type: 'error' });
                setLoading(false);
                return;
            }

            const email = data.email;

            // 2) Ask Supabase Auth to send an email OTP
            const { error: otpError } = await supabase.auth.signInWithOtp({
                email,
            });

            if (otpError) {
                setStatus({ msg: '// FAILED TO SEND OTP', type: 'error' });
                setLoading(false);
                return;
            }

            setStatus({ msg: '// OTP SENT TO EMAIL', type: 'success' });
            setOtpRequested(true);
        } catch (err) {
            console.error(err);
            setStatus({ msg: '// SYSTEM ERROR', type: 'error' });
        } finally {
            setLoading(false);
        }
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        clearErrors();

        if (!otp) {
            setStatus({ msg: '// OTP REQUIRED', type: 'error' });
            return;
        }

        setLoading(true);
        setStatus({ msg: '// VERIFYING...', type: '' });

        try {
            // Look up email again for verification
            const { data, error } = await supabase
                .from("app_users")
                .select("email")
                .eq("user_id", userId)
                .single();

            if (error || !data) {
                setStatus({ msg: '// UNKNOWN USER ID', type: 'error' });
                setLoading(false);
                return;
            }

            const email = data.email;

            const { data: verifyData, error: verifyError } = await supabase.auth.verifyOtp({
                email,
                token: otp,
                type: "email",
            });

            if (verifyError || !verifyData?.session) {
                setStatus({ msg: '// INVALID OR EXPIRED OTP', type: 'error' });
                setLoading(false);
                return;
            }

            const token = verifyData.session.access_token;
            if (token) {
                localStorage.setItem("supabaseJwt", token);
            }

            setStatus({ msg: `// ACCESS GRANTED. WELCOME ${userId}`, type: 'success' });
        } catch (err) {
            console.error(err);
            setStatus({ msg: '// VERIFICATION FAILED', type: 'error' });
        } finally {
            setLoading(false);
        }
    };

    return (
        <main className="login-page">
            <div className="login-card">
                <div className="card-header">
                    <h1 className="card-title flicker">
                        AUTORED&nbsp;<span>APT</span>
                    </h1>
                    <div className="card-divider" />
                    <p className="card-subtitle">Secure Access Portal</p>
                </div>

                <form className="login-form" onSubmit={otpRequested ? handleLogin : handleGetOtp} noValidate>
                    <div className="form-group">
                        <label htmlFor="userId" className="form-label">Operator ID</label>
                        <input
                            id="userId"
                            type="text"
                            className="form-input"
                            placeholder="Enter your user ID"
                            value={userId}
                            onChange={(e) => setUserId(e.target.value)}
                            disabled={otpRequested || loading}
                            autoComplete="username"
                            spellCheck={false}
                        />
                    </div>

                    {otpRequested && (
                        <div className="form-group">
                            <label htmlFor="otp" className="form-label">Access Token (OTP)</label>
                            <input
                                id="otp"
                                type="text"
                                className="form-input"
                                placeholder="Enter 6-digit code"
                                value={otp}
                                onChange={(e) => setOtp(e.target.value)}
                                disabled={loading}
                                autoComplete="one-time-code"
                                maxLength={6}
                            />
                        </div>
                    )}

                    <p className={`form-status ${status.type}`}>
                        {status.msg}&nbsp;
                    </p>

                    <button
                        type="submit"
                        className="btn-submit"
                        disabled={loading}
                    >
                        <span>
                            {loading
                                ? 'PROCESSING...'
                                : (otpRequested ? 'VALIDATE ACCESS' : 'GET ACCESS KEY')}
                        </span>
                    </button>

                    {otpRequested && (
                        <div className="register-row" style={{ marginTop: '15px' }}>
                            Didn't get the key?
                            <button
                                type="button"
                                onClick={handleGetOtp}
                                style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', marginLeft: '5px', textTransform: 'uppercase', fontSize: 'inherit', letterSpacing: 'inherit' }}
                                disabled={loading}
                            >
                                Resend
                            </button>
                        </div>
                    )}
                </form>
            </div>
        </main>
    );
}

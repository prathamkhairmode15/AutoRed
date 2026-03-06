import { useEffect, useRef } from 'react';

const ParticleCanvas = () => {
    const canvasRef = useRef(null);
    const mouseRef = useRef({ x: window.innerWidth / 2, y: window.innerHeight / 2, radius: 200 });
    const particlesRef = useRef([]);

    useEffect(() => {
        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        let animationFrameId;

        const resize = () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            init();
        };

        class Particle {
            constructor() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                // Make particles slightly bigger and more varied
                this.size = Math.random() * 2.5 + 1.2;
                // Movement speed (internal drift)
                this.vx = (Math.random() * 1 - 0.5) * 0.35;
                this.vy = (Math.random() * 1 - 0.5) * 0.35;
            }

            draw(px, py) {
                // Apply global parallax offsets
                const drawX = this.x + px;
                const drawY = this.y + py;

                // Brighter red for visibility
                ctx.fillStyle = '#ff3333';
                ctx.beginPath();
                ctx.arc(drawX, drawY, this.size, 0, Math.PI * 2);
                ctx.closePath();
                ctx.fill();
            }

            update(mouseX, mouseY) {
                this.x += this.vx;
                this.y += this.vy;

                // Infinite wrap-around
                if (this.x < -50) this.x = canvas.width + 50;
                if (this.x > canvas.width + 50) this.x = -50;
                if (this.y < -50) this.y = canvas.height + 50;
                if (this.y > canvas.height + 50) this.y = -50;

                // Mouse interaction (repulsion)
                const dx = mouseX - this.x;
                const dy = mouseY - this.y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < mouseRef.current.radius) {
                    const force = (mouseRef.current.radius - distance) / mouseRef.current.radius;
                    const dirX = dx / (distance || 1);
                    const dirY = dy / (distance || 1);
                    this.x -= dirX * force * 4.5;
                    this.y -= dirY * force * 4.5;
                }
            }
        }

        const init = () => {
            particlesRef.current = [];
            // Increase particle density slightly
            const numberOfParticles = Math.floor((canvas.width * canvas.height) / 7500);
            for (let i = 0; i < numberOfParticles; i++) {
                particlesRef.current.push(new Particle());
            }
        };

        const connect = (px, py, mouseX, mouseY) => {
            const particles = particlesRef.current;
            const threshold = 150;

            for (let a = 0; a < particles.length; a++) {
                for (let b = a + 1; b < particles.length; b++) {
                    const dx = particles[a].x - particles[b].x;
                    const dy = particles[a].y - particles[b].y;
                    const distance = Math.sqrt(dx * dx + dy * dy);

                    if (distance < threshold) {
                        const opacity = (1 - (distance / threshold)) * 0.45;
                        const drawX1 = particles[a].x + px;
                        const drawY1 = particles[a].y + py;
                        const drawX2 = particles[b].x + px;
                        const drawY2 = particles[b].y + py;

                        ctx.strokeStyle = `rgba(255, 30, 30, ${opacity})`;
                        ctx.lineWidth = 1.2;
                        ctx.beginPath();
                        ctx.moveTo(drawX1, drawY1);
                        ctx.lineTo(drawX2, drawY2);
                        ctx.stroke();

                        // Enhanced interactive glow
                        const mdx = mouseX - particles[a].x;
                        const mdy = mouseY - particles[a].y;
                        const mDist = Math.sqrt(mdx * mdx + mdy * mdy);
                        if (mDist < mouseRef.current.radius) {
                            ctx.strokeStyle = `rgba(255, 50, 50, ${opacity * 1.8})`;
                            ctx.shadowBlur = 12;
                            ctx.shadowColor = '#ff2222';
                            ctx.stroke();
                            ctx.shadowBlur = 0; // Reset blur for performance
                        }
                    }
                }
            }
        };

        const animate = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            const mouseX = mouseRef.current.x ?? centerX;
            const mouseY = mouseRef.current.y ?? centerY;

            // Increased parallax factor (0.12) to make the shift very visible
            const px = (centerX - mouseX) * 0.12;
            const py = (centerY - mouseY) * 0.12;

            for (let i = 0; i < particlesRef.current.length; i++) {
                particlesRef.current[i].update(mouseX, mouseY);
                particlesRef.current[i].draw(px, py);
            }

            connect(px, py, mouseX, mouseY);
            animationFrameId = requestAnimationFrame(animate);
        };

        const handleMouseMove = (e) => {
            mouseRef.current.x = e.clientX;
            mouseRef.current.y = e.clientY;
        };

        window.addEventListener('resize', resize);
        window.addEventListener('mousemove', handleMouseMove);

        resize();
        animate();

        return () => {
            window.removeEventListener('resize', resize);
            window.removeEventListener('mousemove', handleMouseMove);
            cancelAnimationFrame(animationFrameId);
        };
    }, []);

    return (
        <canvas
            ref={canvasRef}
            className="bg-canvas"
            style={{
                position: 'fixed',
                top: 0,
                left: 0,
                width: '100%',
                height: '100%',
                zIndex: 1, // Ensure it's above the body background but behind other overlays (which start at zIndex: 1 in original css)
                pointerEvents: 'none',
                backgroundColor: 'transparent'
            }}
        />
    );
};

export default ParticleCanvas;

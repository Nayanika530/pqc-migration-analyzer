/**
 * Quantum Atom Background Component
 * - Solid deep blue core sphere with luminous nucleus
 * - Softly blended cyan wireframe with glowing data nodes
 * - Surrounding concentric vortex of softly glowing particles
 * - Scroll-driven dynamic rotation and parallax movement (cursor tracking disabled)
 */

(function () {
    'use strict';

    if (typeof THREE === 'undefined') {
        var script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js';
        script.onload = initQuantumAtomBackground;
        document.head.appendChild(script);
    } else {
        initQuantumAtomBackground();
    }

    // Helper: generate a soft radial glow point texture dynamically
    function createGlowTexture() {
        var canvas = document.createElement('canvas');
        canvas.width = 64;
        canvas.height = 64;
        var ctx = canvas.getContext('2d');
        
        var gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
        gradient.addColorStop(0.0, 'rgba(255, 255, 255, 1.0)');
        gradient.addColorStop(0.2, 'rgba(180, 235, 255, 0.85)');
        gradient.addColorStop(0.5, 'rgba(0, 160, 255, 0.35)');
        gradient.addColorStop(0.8, 'rgba(0, 70, 200, 0.1)');
        gradient.addColorStop(1.0, 'rgba(0, 20, 80, 0.0)');
        
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, 64, 64);
        
        var texture = new THREE.CanvasTexture(canvas);
        texture.needsUpdate = true;
        return texture;
    }

    function initQuantumAtomBackground() {
        var container = document.getElementById('particle-bg');
        if (!container) {
            container = document.createElement('div');
            container.id = 'particle-bg';
            document.body.insertBefore(container, document.body.firstChild);
        }

        // Clean previous children if any
        container.innerHTML = '';

        // Container styles
        container.style.position = 'fixed';
        container.style.top = '0';
        container.style.left = '0';
        container.style.width = '100vw';
        container.style.height = '100vh';
        container.style.zIndex = '-1';
        container.style.pointerEvents = 'none';
        container.style.overflow = 'hidden';
        container.style.backgroundColor = '#000000';

        const scene = new THREE.Scene();
        scene.fog = new THREE.FogExp2(0x000000, 0.04);

        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        camera.position.z = 6.0;

        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

        const canvas = renderer.domElement;
        canvas.style.display = 'block';
        canvas.style.position = 'absolute';
        canvas.style.top = '0';
        canvas.style.left = '0';
        canvas.style.width = '100%';
        canvas.style.height = '100%';
        canvas.style.zIndex = '-1';
        canvas.style.opacity = '0.78'; /* Softly blended and balanced */
        canvas.style.pointerEvents = 'none';
        container.appendChild(canvas);

        const glowTexture = createGlowTexture();

        // 1. Center Core Sphere (Slightly larger, balanced size)
        const coreGeometry = new THREE.IcosahedronGeometry(3.0, 3);
        const coreMaterial = new THREE.MeshBasicMaterial({ 
            color: 0x041638,
            transparent: true,
            opacity: 0.72
        });
        const coreMesh = new THREE.Mesh(coreGeometry, coreMaterial);
        scene.add(coreMesh);

        // Inner glowing nucleus
        const innerGeo = new THREE.IcosahedronGeometry(1.8, 2);
        const innerMat = new THREE.MeshBasicMaterial({
            color: 0x004ad9,
            transparent: true,
            opacity: 0.32,
            blending: THREE.AdditiveBlending
        });
        const innerMesh = new THREE.Mesh(innerGeo, innerMat);
        coreMesh.add(innerMesh);

        // 2. Center Wireframe (Softly Blended Cyan Lattice)
        const wireframeMaterial = new THREE.LineBasicMaterial({ 
            color: 0x00c8f8, 
            transparent: true, 
            opacity: 0.48,
            blending: THREE.AdditiveBlending
        });
        const wireframeGeometry = new THREE.WireframeGeometry(coreGeometry);
        const wireframe = new THREE.LineSegments(wireframeGeometry, wireframeMaterial);
        coreMesh.add(wireframe);

        // 3. Node Points on the Wireframe Vertices
        const nodeMaterial = new THREE.PointsMaterial({
            color: 0xa0e8ff,
            size: 0.09,
            map: glowTexture,
            transparent: true,
            opacity: 0.78,
            blending: THREE.AdditiveBlending,
            depthWrite: false
        });
        const nodes = new THREE.Points(coreGeometry, nodeMaterial);
        coreMesh.add(nodes);

        // 4. Surrounding Concentric Particle Vortex Rings
        const particleCount = 16000;
        const particleGeo = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        const basePositions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        const colorCyan = new THREE.Color(0x00e5ff);
        const colorBlue = new THREE.Color(0x2979ff);
        const colorElectric = new THREE.Color(0x651fff);

        for (let i = 0; i < particleCount; i++) {
            // Layered orbital rings around the core globe
            const ringType = Math.random();
            let radius, y;

            if (ringType < 0.45) {
                // Inner orbital ring
                radius = 3.4 + Math.random() * 1.6;
                y = (Math.random() - 0.5) * 2.5;
            } else if (ringType < 0.8) {
                // Mid orbital swirling band
                radius = 4.8 + Math.random() * 2.4;
                y = (Math.random() - 0.5) * 4.8;
            } else {
                // Outer cosmic ambient field
                radius = 6.8 + Math.random() * 3.2;
                y = (Math.random() - 0.5) * 6.5;
            }

            const theta = Math.random() * Math.PI * 2;
            const x = Math.cos(theta) * radius;
            const z = Math.sin(theta) * radius;

            positions[i * 3] = x;
            positions[i * 3 + 1] = y;
            positions[i * 3 + 2] = z;

            basePositions[i * 3] = x;
            basePositions[i * 3 + 1] = y;
            basePositions[i * 3 + 2] = z;

            // Palette variation
            const cRatio = Math.random();
            let pColor = colorCyan;
            if (cRatio > 0.55) pColor = colorBlue;
            else if (cRatio > 0.88) pColor = colorElectric;

            colors[i * 3] = pColor.r;
            colors[i * 3 + 1] = pColor.g;
            colors[i * 3 + 2] = pColor.b;
        }

        particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        particleGeo.setAttribute('basePosition', new THREE.BufferAttribute(basePositions, 3));
        particleGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const particleMaterial = new THREE.PointsMaterial({
            vertexColors: true,
            size: 0.065,
            map: glowTexture,
            transparent: true,
            opacity: 0.62,
            blending: THREE.AdditiveBlending,
            depthWrite: false
        });

        const vortex = new THREE.Points(particleGeo, particleMaterial);
        scene.add(vortex);

        // Scroll Tracking for Dynamic Globe Movement
        let currentScroll = 0;
        let targetScroll = 0;

        function updateScroll() {
            targetScroll = window.pageYOffset || document.documentElement.scrollTop || 0;
        }

        window.addEventListener('scroll', updateScroll, { passive: true });
        updateScroll();

        // Cursor Tracking for Dynamic Particle Movement
        let mouseX = 0, mouseY = 0;
        let targetMouseX = 0, targetMouseY = 0;

        window.addEventListener('mousemove', function (e) {
            targetMouseX = (e.clientX / window.innerWidth) * 2 - 1;
            targetMouseY = -(e.clientY / window.innerHeight) * 2 + 1;
        });

        window.addEventListener('touchmove', function (e) {
            if (e.touches.length > 0) {
                targetMouseX = (e.touches[0].clientX / window.innerWidth) * 2 - 1;
                targetMouseY = -(e.touches[0].clientY / window.innerHeight) * 2 + 1;
            }
        }, { passive: true });

        window.addEventListener('resize', function () {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        const clock = new THREE.Clock();

        function animate() {
            requestAnimationFrame(animate);
            const elapsedTime = clock.getElapsedTime();

            // Smooth scroll interpolation
            currentScroll += (targetScroll - currentScroll) * 0.07;
            const scrollRot = currentScroll * 0.003;
            const scrollYOffset = currentScroll * 0.0018;

            // Smooth cursor interpolation for particles
            mouseX += (targetMouseX - mouseX) * 0.06;
            mouseY += (targetMouseY - mouseY) * 0.06;

            // 1. Globe core rotation is strictly scroll-driven + gentle idle spin (not cursor-tied)
            coreMesh.rotation.y = elapsedTime * 0.05 + scrollRot;
            coreMesh.rotation.x = Math.sin(elapsedTime * 0.2) * 0.12 + scrollRot * 0.6;
            coreMesh.rotation.z = Math.cos(elapsedTime * 0.15) * 0.08;
            coreMesh.position.y = -scrollYOffset;

            // 2. Surrounding particle vortex dynamically follows & tilts with the CURSOR and scroll
            vortex.rotation.y = -elapsedTime * 0.025 - scrollRot * 0.75 + mouseX * 0.45;
            vortex.rotation.x = scrollRot * 0.4 - mouseY * 0.35;
            vortex.rotation.z = mouseX * 0.15;
            vortex.position.x = mouseX * 0.55;
            vortex.position.y = -scrollYOffset + mouseY * 0.35;

            // 3. Dynamic individual particle ripple & deflection based on cursor proximity
            const cursorWorldX = mouseX * 4.5;
            const cursorWorldY = mouseY * 3.8;

            const pos = vortex.geometry.attributes.position.array;
            const basePos = vortex.geometry.attributes.basePosition.array;

            for (let i = 0; i < particleCount; i++) {
                const ix = i * 3;
                const iy = i * 3 + 1;
                const iz = i * 3 + 2;

                const bx = basePos[ix];
                const by = basePos[iy];
                const bz = basePos[iz];

                // Sine wave harmonic distortion
                const wave = Math.sin(by * 1.8 + elapsedTime * 1.8 + scrollRot) * 0.3;
                
                // Cursor particle wave deflection
                const dx = bx - cursorWorldX;
                const dy = by - cursorWorldY;
                const distSq = dx * dx + dy * dy;
                const repel = Math.exp(-distSq * 0.16) * 0.55;

                pos[ix] = bx + Math.cos(elapsedTime + by) * wave + dx * repel;
                pos[iy] = by + Math.sin(elapsedTime * 0.7 + bx) * 0.12 + dy * repel;
                pos[iz] = bz + Math.sin(elapsedTime + bx) * wave;
            }
            
            vortex.geometry.attributes.position.needsUpdate = true;
            renderer.render(scene, camera);
        }

        animate();
    }
})();

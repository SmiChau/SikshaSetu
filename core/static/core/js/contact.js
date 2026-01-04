// Toggle Instructor Fields
    function toggleInstructorFields() {
        const purpose = document.getElementById('purpose').value;
        const instructorFields = document.getElementById('instructorFields');
        const expertise = document.getElementById('expertise');
        const experience = document.getElementById('experience');

        if (purpose === 'instructor') {
            instructorFields.classList.add('active');
            expertise.required = true;
            experience.required = true;
        } else {
            instructorFields.classList.remove('active');
            expertise.required = false;
            experience.required = false;
        }
    }

    // Form Validation & Submission
    document.getElementById('contactForm').addEventListener('submit', function (event) {
        event.preventDefault();
        event.stopPropagation();

        const form = this;
        let isValid = true;

        // Custom Bootstrap-like validation
        const requiredInputs = form.querySelectorAll('input[required], select[required], textarea[required]');

        requiredInputs.forEach(input => {
            if (!input.value.trim()) {
                input.classList.add('is-invalid');
                isValid = false;
            } else {
                input.classList.remove('is-invalid');
            }
        });

        // Email validation
        const emailInput = document.getElementById('email');
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(emailInput.value.trim())) {
            emailInput.classList.add('is-invalid');
            isValid = false;
        }

        if (isValid) {
            // Simulate API call
            const submitBtn = document.getElementById('submitBtn');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Sending...';

            setTimeout(() => {
                document.getElementById('form-container').style.display = 'none';
                document.getElementById('successMessage').style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
                form.reset();
            }, 1500);
        }
    });

    // Remove invalid class on input
    document.querySelectorAll('.form-control-custom').forEach(input => {
        input.addEventListener('input', function () {
            if (this.value.trim()) {
                this.classList.remove('is-invalid');
            }
        });
    });
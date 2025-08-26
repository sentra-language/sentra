// Sentra Documentation JavaScript

// Mobile navigation toggle
document.addEventListener('DOMContentLoaded', function() {
    const navToggle = document.getElementById('nav-toggle');
    const navMenu = document.getElementById('nav-menu');
    
    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
        });
        
        // Close menu when clicking outside
        document.addEventListener('click', function(event) {
            if (!navToggle.contains(event.target) && !navMenu.contains(event.target)) {
                navMenu.classList.remove('active');
            }
        });
    }
    
    // Smooth scrolling for anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                e.preventDefault();
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Copy code button for code blocks
    const codeBlocks = document.querySelectorAll('pre code');
    codeBlocks.forEach(function(codeBlock) {
        const copyButton = document.createElement('button');
        copyButton.className = 'copy-code-btn';
        copyButton.innerHTML = '📋 Copy';
        copyButton.style.cssText = `
            position: absolute;
            top: 10px;
            right: 10px;
            background: #2d3748;
            color: #e2e8f0;
            border: 1px solid #4a5568;
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 12px;
            cursor: pointer;
            z-index: 10;
        `;
        
        const pre = codeBlock.parentElement;
        pre.style.position = 'relative';
        pre.appendChild(copyButton);
        
        copyButton.addEventListener('click', function() {
            const text = codeBlock.textContent || codeBlock.innerText;
            navigator.clipboard.writeText(text).then(function() {
                copyButton.innerHTML = '✅ Copied!';
                setTimeout(function() {
                    copyButton.innerHTML = '📋 Copy';
                }, 2000);
            });
        });
    });
    
    // Table of contents generator
    function generateTOC() {
        const tocContainer = document.querySelector('.table-of-contents');
        if (!tocContainer) return;
        
        const headings = document.querySelectorAll('h2, h3, h4');
        const toc = document.createElement('ul');
        toc.className = 'toc-list';
        
        headings.forEach(function(heading, index) {
            // Add ID if not present
            if (!heading.id) {
                heading.id = 'heading-' + index;
            }
            
            const li = document.createElement('li');
            li.className = 'toc-item toc-' + heading.tagName.toLowerCase();
            
            const link = document.createElement('a');
            link.href = '#' + heading.id;
            link.textContent = heading.textContent;
            link.className = 'toc-link';
            
            li.appendChild(link);
            toc.appendChild(li);
        });
        
        tocContainer.appendChild(toc);
    }
    
    generateTOC();
    
    // Highlight current section in TOC
    function highlightCurrentSection() {
        const tocLinks = document.querySelectorAll('.toc-link');
        const headings = document.querySelectorAll('h2, h3, h4');
        
        if (tocLinks.length === 0 || headings.length === 0) return;
        
        const scrollPosition = window.scrollY;
        let currentSection = '';
        
        headings.forEach(function(heading) {
            const rect = heading.getBoundingClientRect();
            if (rect.top <= 100) {
                currentSection = heading.id;
            }
        });
        
        tocLinks.forEach(function(link) {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + currentSection) {
                link.classList.add('active');
            }
        });
    }
    
    window.addEventListener('scroll', highlightCurrentSection);
    
    // Search functionality (if search input exists)
    const searchInput = document.querySelector('#search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const query = this.value.toLowerCase();
            const searchResults = document.querySelector('#search-results');
            
            if (query.length < 2) {
                searchResults.innerHTML = '';
                searchResults.style.display = 'none';
                return;
            }
            
            // Simple search implementation
            // In a real implementation, you'd want to use a proper search index
            const content = document.querySelectorAll('h1, h2, h3, h4, h5, h6, p');
            const results = [];
            
            content.forEach(function(element) {
                const text = element.textContent.toLowerCase();
                if (text.includes(query)) {
                    results.push({
                        title: element.textContent,
                        element: element
                    });
                }
            });
            
            displaySearchResults(results.slice(0, 10));
        });
    }
    
    function displaySearchResults(results) {
        const searchResults = document.querySelector('#search-results');
        if (!searchResults) return;
        
        if (results.length === 0) {
            searchResults.innerHTML = '<p>No results found.</p>';
        } else {
            const resultsList = document.createElement('ul');
            resultsList.className = 'search-results-list';
            
            results.forEach(function(result) {
                const li = document.createElement('li');
                const link = document.createElement('a');
                link.textContent = result.title;
                link.href = '#' + (result.element.id || '');
                li.appendChild(link);
                resultsList.appendChild(li);
            });
            
            searchResults.innerHTML = '';
            searchResults.appendChild(resultsList);
        }
        
        searchResults.style.display = 'block';
    }
    
    // Syntax highlighting enhancement
    if (typeof Prism !== 'undefined') {
        // Add language labels to code blocks
        const codeBlocks = document.querySelectorAll('pre[class*="language-"]');
        codeBlocks.forEach(function(block) {
            const language = block.className.match(/language-(\w+)/);
            if (language) {
                const label = document.createElement('div');
                label.className = 'code-language-label';
                label.textContent = language[1];
                label.style.cssText = `
                    position: absolute;
                    top: -1px;
                    right: -1px;
                    background: #4a5568;
                    color: #e2e8f0;
                    padding: 2px 8px;
                    font-size: 10px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    border-top-right-radius: 8px;
                    border-bottom-left-radius: 4px;
                `;
                
                block.style.position = 'relative';
                block.appendChild(label);
            }
        });
    }
    
    // Add fade-in animation to elements
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in-up');
            }
        });
    }, observerOptions);
    
    const animateElements = document.querySelectorAll('.card, .feature-card, .code-example');
    animateElements.forEach(function(element) {
        observer.observe(element);
    });
    
    // Back to top button
    const backToTopButton = document.createElement('button');
    backToTopButton.innerHTML = '↑';
    backToTopButton.className = 'back-to-top';
    backToTopButton.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #2563eb;
        color: white;
        border: none;
        border-radius: 50%;
        width: 50px;
        height: 50px;
        font-size: 20px;
        cursor: pointer;
        opacity: 0;
        transition: all 0.3s ease;
        z-index: 1000;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    `;
    
    document.body.appendChild(backToTopButton);
    
    backToTopButton.addEventListener('click', function() {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
    
    window.addEventListener('scroll', function() {
        if (window.scrollY > 300) {
            backToTopButton.style.opacity = '1';
            backToTopButton.style.transform = 'translateY(0)';
        } else {
            backToTopButton.style.opacity = '0';
            backToTopButton.style.transform = 'translateY(10px)';
        }
    });
});
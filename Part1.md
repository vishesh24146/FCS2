# BeYou Backend Technical Deep Dive - Part 1: Core Architecture & Authentication

## 🏗️ **BACKEND ARCHITECTURE OVERVIEW**

### **System Design Philosophy**
BeYou follows a **security-first, modular architecture** with these core principles:
- **Defense in Depth**: Multiple security layers at every level
- **Separation of Concerns**: Each app handles specific functionality
- **Cryptographic Foundation**: Built-in encryption and blockchain integrity
- **Scalable Design**: Prepared for production deployment

### **Application Structure**
```
BeYou/
├── users/          # Authentication, profiles, verification, key management
├── friends/        # Social connections, notifications
├── messaging/      # Encrypted messaging, blockchain integration
├── marketplace/    # E-commerce functionality
└── social_media/   # Main project configuration
```

---

## 🔐 **AUTHENTICATION SYSTEM DEEP DIVE**

### **Custom Authentication Backend**
**File**: `users/auth_backend.py`

**Why Custom Backend?**
- **Comprehensive Logging**: Every login attempt tracked
- **Security Monitoring**: Failed attempts logged with IP/User-Agent
- **Audit Trail**: Complete authentication history
- **Threat Detection**: Pattern analysis for suspicious activity

**Implementation Details:**
```python
class LoggingModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Create login activity entry BEFORE authentication
        login_activity = LoginActivity(
            username=username,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            was_successful=False
        )
        
        # Attempt authentication
        user = super().authenticate(request, username, password, **kwargs)
        
        # Update activity based on result
        if user:
            login_activity.user = user
            login_activity.was_successful = True
            login_activity.session_key = request.session.session_key
        else:
            login_activity.failure_reason = "Invalid credentials"
        
        login_activity.save()
        return user
```

**Key Features:**
1. **Pre-Authentication Logging**: Records attempt before validation
2. **IP Tracking**: Captures real IP through proxies (X-Forwarded-For)
3. **Session Correlation**: Links successful logins to session keys
4. **Failure Analysis**: Categorizes failure reasons

### **Middleware Security Layer**
**File**: `users/middleware.py`

**Dual Middleware System:**

#### **1. LoginAttemptMiddleware**
**Purpose**: Catch form submission failures that bypass authentication backend
```python
def process_request(self, request):
    if request.path == '/users/login/' and request.method == 'POST':
        # Log form submission attempts
        # Prevents duplicate logging with flag system
```

#### **2. AuthenticationMiddleware**
**Purpose**: Redirect authenticated users from public pages
```python
def __call__(self, request):
    restricted_urls = ['/landing/', '/login/', '/register/']
    if request.user.is_authenticated and request.path in restricted_urls:
        return redirect('profile')
```

**Why This Approach?**
- **Complete Coverage**: No authentication attempt goes unlogged
- **User Experience**: Seamless redirects for authenticated users
- **Security**: Prevents information disclosure through timing attacks

### **Two-Factor Authentication (2FA)**
**Implementation**: TOTP (Time-based One-Time Password)

**Setup Process:**
1. **Secret Generation**: `pyotp.random_base32()` creates unique secret
2. **QR Code Creation**: Provisioning URI for authenticator apps
3. **Verification**: User must verify setup with valid TOTP code
4. **Storage**: Secret stored encrypted in user profile

**Password Reset Integration:**
```python
def password_reset_verify(request, reset_id):
    # Requires TOTP verification for password reset
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(token):
        # Allow password change
```

**Security Benefits:**
- **Phishing Resistant**: TOTP codes change every 30 seconds
- **No SMS Vulnerabilities**: App-based authentication
- **Offline Capable**: Works without internet connection

---

## 🔑 **CRYPTOGRAPHIC KEY MANAGEMENT**

### **Key Generation System**
**File**: `messaging/utils.py`

**Dual Key Pair Architecture:**
Each user gets **two RSA key pairs**:
1. **Signing Keys**: For message authentication (digital signatures)
2. **Encryption Keys**: For message confidentiality (E2E encryption)

**Key Generation Process:**
```python
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard RSA exponent
        key_size=2048,          # 2048-bit keys (secure until ~2030)
        backend=default_backend()
    )
    
    # Serialize to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No password protection
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
```

**Why This Design?**
- **Separation of Concerns**: Different keys for different purposes
- **Forward Secrecy**: Keys can be rotated independently
- **Standard Compliance**: Uses industry-standard RSA with PKCS#8
- **Interoperability**: PEM format works with all crypto libraries

### **Key Storage Strategy**
**Database Storage** (`UserKey` model):
- **Public Keys**: Stored in database with hash index
- **Key Type**: Signing vs Encryption differentiation
- **Active Status**: Allows key rotation without data loss

**Private Key Handling**:
- **Never Stored**: Private keys never touch the database
- **Session Temporary**: Stored in session during key generation
- **User Download**: User must download and store securely
- **Re-upload System**: Users can re-upload keys when needed

**Security Rationale:**
```python
class UserKey(models.Model):
    public_key_hash = models.CharField(max_length=64, db_index=True, unique=True)
    
    def save(self, *args, **kwargs):
        # Generate hash for fast lookups
        if not self.public_key_hash and self.public_key:
            import hashlib
            self.public_key_hash = hashlib.sha256(self.public_key.encode()).hexdigest()
```

**Benefits:**
- **Zero Knowledge**: Server never knows private keys
- **Performance**: Hash-based key lookups
- **Scalability**: Unique constraints prevent duplicates

---

## 📊 **USER MANAGEMENT & VERIFICATION**

### **Extended User Model**
**File**: `users/models.py`

**CustomUser Extensions:**
```python
class CustomUser(AbstractUser):
    phone_number = models.CharField(max_length=15, unique=True)
    email = models.EmailField(unique=True, db_index=True)
    profile_picture = models.ImageField(upload_to='profile_pics/')
    bio = models.TextField(max_length=500)
    is_verified = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32)  # 2FA secret
    
    # Verification system
    id_document = models.ImageField(upload_to='verification_docs/')
    verification_status = models.CharField(choices=[...])
    verification_submitted_at = models.DateTimeField()
    verification_processed_at = models.DateTimeField()
    verification_notes = models.TextField()  # Admin notes
```

**Why These Fields?**
- **Phone Uniqueness**: Prevents multiple accounts per phone
- **Email Indexing**: Fast lookups for authentication
- **Verification Workflow**: Complete audit trail
- **Admin Notes**: Transparency in verification decisions

### **Verification Workflow**
**Multi-Stage Process:**

1. **User Submission**:
   - Upload government ID document
   - Provide reason for verification request
   - System timestamps submission

2. **Admin Review**:
   - Staff access verification dashboard
   - Review documents and user history
   - Make approve/reject decision with notes

3. **Status Updates**:
   - User notified of decision
   - Verification status tracked in database
   - Premium features unlocked for verified users

**Database Design:**
```python
verification_status = models.CharField(
    choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ],
    default='pending'
)
```

**Security Considerations:**
- **Document Storage**: Secure file upload handling
- **Admin Access**: Staff-only verification views
- **Audit Trail**: Complete verification history
- **Privacy**: Verification documents protected

---

## 🛡️ **SECURITY MONITORING SYSTEM**

### **Login Activity Tracking**
**File**: `users/models.py` - `LoginActivity` model

**Comprehensive Logging:**
```python
class LoginActivity(models.Model):
    user = models.ForeignKey(CustomUser, null=True, blank=True)
    username = models.CharField(max_length=150)  # Store even for failed attempts
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    was_successful = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=100)
    session_key = models.CharField(max_length=100)
```

**Analytics Capabilities:**
- **Success/Failure Rates**: Track authentication patterns
- **IP Analysis**: Detect suspicious login locations
- **User Agent Tracking**: Identify potential bot attacks
- **Session Correlation**: Link activities to user sessions
- **Failure Pattern Analysis**: Identify brute force attempts

### **Admin Security Dashboard**
**File**: `users/views.py` - `login_logs` function

**Real-time Monitoring:**
```python
@login_required
@user_passes_test(lambda u: u.is_staff)
def login_logs(request):
    # Filter capabilities
    activities = LoginActivity.objects.all()
    
    # Apply filters (username, IP, date range, status)
    if username:
        activities = activities.filter(username__icontains=username)
    
    # Statistics
    total_logins = activities.count()
    successful_logins = activities.filter(was_successful=True).count()
    failed_logins = activities.filter(was_successful=False).count()
    
    # Threat analysis
    failure_counts = {}  # Count failures by username
    most_failed = sorted(failure_counts.items(), key=lambda x: x[1], reverse=True)
```

**Dashboard Features:**
- **Real-time Filtering**: Search by user, IP, date, status
- **Statistical Overview**: Success rates, unique users/IPs
- **Threat Detection**: Most failed login attempts
- **Recent Activity**: Latest failed attempts for quick response

---

## 🔒 **USER BLOCKING & REPORTING SYSTEM**

### **User Blocking Mechanism**
**File**: `users/models.py` - `UserBlock` model

**Bidirectional Blocking:**
```python
class UserBlock(models.Model):
    blocker = models.ForeignKey(CustomUser, related_name='blocking')
    blocked_user = models.ForeignKey(CustomUser, related_name='blocked_by')
    reason = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('blocker', 'blocked_user')
```

**System-wide Block Enforcement:**
- **Messaging**: Blocked users cannot start conversations
- **Friend Requests**: Automatic rejection of requests
- **Profile Access**: Limited profile visibility
- **Search Results**: Blocked users filtered from searches

### **Comprehensive Reporting System**
**File**: `users/models.py` - `Report` model

**Multi-type Reporting:**
```python
class Report(models.Model):
    REPORT_TYPES = [
        ('user', 'User Report'),
        ('message', 'Message Report'),
        ('item', 'Marketplace Item Report'),
    ]
    
    reporter = models.ForeignKey(CustomUser, related_name='submitted_reports')
    reported_user = models.ForeignKey(CustomUser, related_name='reports_against')
    reported_message = models.UUIDField()  # Message ID
    reported_item = models.UUIDField()     # Item ID
    
    report_type = models.CharField(choices=REPORT_TYPES)
    reason = models.TextField()
    screenshot = models.ImageField(upload_to='report_evidence/')
    
    status = models.CharField(choices=STATUS_CHOICES, default='pending')
    admin_notes = models.TextField()
    action_taken = models.CharField(max_length=255)
```

**Admin Moderation Workflow:**
1. **Report Submission**: Users can report content with evidence
2. **Admin Review**: Staff dashboard for report management
3. **Investigation**: Status tracking through review process
4. **Action Taking**: Warning, temporary ban, permanent ban, content deletion
5. **Documentation**: Complete audit trail of moderation actions

---

This completes Part 1 of the technical deep dive, covering the foundational security and authentication systems. The architecture demonstrates enterprise-level security practices with comprehensive logging, monitoring, and user management capabilities.
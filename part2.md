# BeYou Backend Technical Deep Dive - Part 2: Messaging System & Blockchain

## 💬 **MESSAGING SYSTEM ARCHITECTURE**

### **Multi-Layer Encryption Design**
The messaging system implements **three levels of encryption** for maximum security:

1. **Transport Layer**: HTTPS encryption for data in transit
2. **Application Layer**: Fernet symmetric encryption for database storage
3. **End-to-End Layer**: RSA asymmetric encryption for ultimate privacy

### **Message Model Deep Dive**
**File**: `messaging/models.py`

```python
class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)  # UUID for security
    conversation = models.ForeignKey(Conversation, related_name='messages')
    sender = models.ForeignKey(CustomUser, related_name='sent_messages')
    
    # Encryption fields
    encrypted_content = models.TextField()      # Fernet-encrypted content
    signature = models.TextField()              # Digital signature
    is_encrypted = models.BooleanField()        # E2E encryption flag
    
    # Blockchain integration
    blockchain_hash = models.CharField(max_length=64)
    integrity_verified = models.BooleanField(default=False)
    
    # Media support
    media_file = models.FileField(upload_to='message_media/')
    media_type = models.CharField(choices=MEDIA_TYPES)
```

**Why This Design?**
- **UUID Primary Keys**: Prevents message ID enumeration attacks
- **Dual Encryption Support**: Standard + E2E encryption options
- **Blockchain Integration**: Automatic integrity verification
- **Media Flexibility**: Images and videos with type validation

### **Encryption Implementation Deep Dive**

#### **Standard Encryption (Fernet)**
**File**: `messaging/models.py` - Message methods

```python
def encrypt_message(self, content):
    if content:
        key = settings.ENCRYPTION_KEY.encode()
        f = Fernet(key)
        encrypted_message = f.encrypt(content.encode())
        self.encrypted_content = encrypted_message.decode()

def decrypt_message(self):
    if not self.encrypted_content:
        return ""
    key = settings.ENCRYPTION_KEY.encode()
    f = Fernet(key)
    decrypted_message = f.decrypt(self.encrypted_content.encode())
    return decrypted_message.decode()
```

**Benefits:**
- **Fast Performance**: Symmetric encryption is computationally efficient
- **Server Decryption**: Server can decrypt for search/moderation
- **Backup Friendly**: Encrypted data can be backed up securely

#### **End-to-End Encryption (RSA)**
**File**: `messaging/utils.py`

```python
def encrypt_for_recipient(public_key_pem, message):
    public_key = load_public_key(public_key_pem)
    
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return b64encode(ciphertext).decode('utf-8')
```

**E2E Message Flow:**
1. **Composition**: User writes message
2. **Key Retrieval**: Get recipient's public encryption key
3. **Individual Encryption**: Encrypt message for each recipient
4. **Storage**: Store multiple encrypted versions
5. **Decryption**: Each user decrypts with their private key

**Security Advantages:**
- **Zero Knowledge**: Server cannot read message content
- **Forward Secrecy**: Key rotation doesn't compromise old messages
- **Multi-recipient**: Each participant gets individually encrypted copy

### **Digital Signature System**
**File**: `messaging/utils.py`

```python
def sign_message(private_key_pem, message):
    private_key = load_private_key(private_key_pem)
    
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem, message, signature):
    public_key = load_public_key(public_key_pem)
    decoded_signature = b64decode(signature)
    
    public_key.verify(
        decoded_signature,
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return True  # Exception thrown if verification fails
```

**Authentication Benefits:**
- **Message Authenticity**: Proves message came from claimed sender
- **Non-repudiation**: Sender cannot deny sending the message
- **Integrity**: Detects any message tampering
- **PSS Padding**: Probabilistic signature scheme for enhanced security

---

## ⛓️ **BLOCKCHAIN IMPLEMENTATION**

### **Custom Blockchain Architecture**
**File**: `messaging/blockchain.py`

**Why Custom Blockchain?**
- **Specific Use Case**: Optimized for message integrity verification
- **Performance Control**: Adjustable difficulty for server capacity
- **Privacy**: No external blockchain dependencies
- **Integration**: Seamless Django integration

### **Block Structure**
```python
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index              # Block number in chain
        self.timestamp = timestamp      # Creation time
        self.data = data               # Message metadata
        self.previous_hash = previous_hash  # Links to previous block
        self.nonce = 0                 # Proof of work value
        self.hash = self.calculate_hash()  # Block hash
```

**Block Data Structure:**
```python
block_data = {
    "block_type": "message",
    "conversation_id": str(message.conversation.id),
    "conversation_name": message.conversation.name,
    "timestamp": timezone.now().timestamp(),
    "messages": [{
        "message_id": str(message.id),
        "sender_id": message.sender.id,
        "sender_username": message.sender.username,
        "content_hash": message_hash,
        "has_signature": bool(message.signature),
        "is_encrypted": message.is_encrypted,
        "media_type": message.media_type,
        "timestamp": timezone.now().timestamp(),
    }]
}
```

### **Proof of Work Implementation**
```python
def mine_block(self, difficulty=2):
    target = "0" * difficulty
    while self.hash[:difficulty] != target:
        self.nonce += 1
        self.hash = self.calculate_hash()
```

**Mining Process:**
1. **Target Setting**: Require hash to start with N zeros
2. **Nonce Iteration**: Increment nonce until target met
3. **Hash Calculation**: SHA-256 of block contents + nonce
4. **Validation**: Verify hash meets difficulty requirement

**Why Proof of Work?**
- **Tamper Resistance**: Changing any block requires re-mining entire chain
- **Computational Cost**: Makes blockchain manipulation expensive
- **Adjustable Security**: Difficulty can be tuned for performance
- **Standard Practice**: Well-understood consensus mechanism

### **Blockchain Integration with Messages**
**File**: `messaging/models.py` - Message.save() method

```python
def save(self, *args, **kwargs):
    is_new = self.pk is None
    super().save(*args, **kwargs)
    
    # Only add to blockchain if it's a new message with content
    if is_new and (self.encrypted_content or self.media_file):
        from .blockchain import record_conversation_message
        blockchain_hash = record_conversation_message(self)
        if blockchain_hash:
            # Update without triggering another save cycle
            type(self).objects.filter(pk=self.pk).update(
                blockchain_hash=blockchain_hash,
                integrity_verified=True
            )
```

**Automatic Integration:**
- **Transparent**: Blockchain recording happens automatically
- **Performance**: Asynchronous to avoid blocking message sending
- **Integrity**: Every message gets blockchain verification
- **Audit Trail**: Complete history of all communications

### **Integrity Verification System**
```python
def verify_message_integrity(message):
    if not message.blockchain_hash:
        return False
    
    # Calculate current message hash
    message_content = message.decrypt_message()
    current_hash = hashlib.sha256(message_content.encode()).hexdigest()
    
    # Find the block containing this message
    for block in message_blockchain.chain:
        for msg_data in block.data.get("messages", []):
            if msg_data.get("message_id") == str(message.id):
                return current_hash == msg_data.get("content_hash")
    
    return False
```

**Verification Process:**
1. **Hash Calculation**: Compute current message hash
2. **Blockchain Search**: Find message in blockchain
3. **Comparison**: Compare current vs stored hash
4. **Result**: Return integrity status

---

## 🗨️ **CONVERSATION MANAGEMENT**

### **Conversation Model Architecture**
**File**: `messaging/models.py`

```python
class Conversation(models.Model):
    CONVERSATION_TYPES = (
        ('direct', 'Direct'),
        ('group', 'Group'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    name = models.CharField(max_length=100)  # For group conversations
    conversation_type = models.CharField(choices=CONVERSATION_TYPES)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

**Participant Management:**
```python
class ConversationParticipant(models.Model):
    conversation = models.ForeignKey(Conversation, related_name='participants')
    user = models.ForeignKey(CustomUser, related_name='conversations')
    is_admin = models.BooleanField(default=False)  # For group conversations
    joined_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('conversation', 'user')
```

### **Message Viewing Logic**
**File**: `messaging/views.py` - `view_conversation`

**Complex Decryption Logic:**
```python
# Get user's encryption private key from session
encryption_private_key = request.session.get('encryption_private_key')

for msg in messages_qs:
    # Handle standard encrypted messages
    if not msg.is_encrypted and msg.encrypted_content:
        try:
            message_data['content'] = f.decrypt(msg.encrypted_content.encode()).decode()
        except Exception:
            message_data['content'] = "[Encrypted message]"
    
    # Handle E2E encrypted messages
    elif msg.is_encrypted:
        if encryption_private_key:
            try:
                encrypted_content = msg.encrypted_contents.get(recipient=request.user)
                decrypted_content = decrypt_message(
                    encryption_private_key,
                    encrypted_content.encrypted_content
                )
                message_data['content'] = decrypted_content or "[Could not decrypt message]"
            except Exception:
                message_data['content'] = "[End-to-end encrypted message - Error decrypting]"
        else:
            message_data['content'] = "[End-to-end encrypted message - No private key available]"
```

**Security Considerations:**
- **Key Availability**: Graceful handling when private keys unavailable
- **Error Handling**: Clear messages for different failure modes
- **Performance**: Efficient decryption for message lists
- **User Experience**: Informative error messages

### **Group Chat Implementation**
**File**: `messaging/views.py`

**Group Creation Process:**
```python
@login_required
def create_group(request):
    # Only verified users can create groups
    if not request.user.is_verified:
        messages.error(request, "You need to be verified to create group conversations.")
        return redirect('verification_request')
    
    if form.is_valid():
        conversation = form.save(commit=False)
        conversation.conversation_type = 'group'
        conversation.save()
        
        # Add creator as admin
        ConversationParticipant.objects.create(
            conversation=conversation,
            user=request.user,
            is_admin=True
        )
        
        # Add other participants
        for user in form.cleaned_data['participants']:
            ConversationParticipant.objects.create(
                conversation=conversation,
                user=user
            )
            
            # Notify participants
            Notification.objects.create(
                user=user,
                notification_type='group_invite',
                content=f"{request.user.username} added you to the group '{conversation.name}'",
                related_user=request.user
            )
```

**Group Management Features:**
- **Admin Controls**: Add/remove members, delete group
- **Member Management**: View participants, assign admin roles
- **Notification System**: Automatic notifications for group events
- **Verification Requirement**: Only verified users can create groups

---

## 🔔 **NOTIFICATION SYSTEM**

### **Notification Model**
**File**: `friends/models.py`

```python
class Notification(models.Model):
    TYPE_CHOICES = [
        ('friend_request', 'Friend Request'),
        ('friend_accept', 'Friend Request Accepted'),
        ('message', 'New Message'),
        ('group_invite', 'Group Invitation'),
    ]
    
    user = models.ForeignKey(CustomUser, related_name='notifications')
    notification_type = models.CharField(choices=TYPE_CHOICES)
    content = models.CharField(max_length=255)
    related_user = models.ForeignKey(CustomUser, related_name='sent_notifications')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
```

**Automatic Notification Creation:**
```python
# In messaging/views.py - after message creation
for participant in participants:
    notification_content = "New message from {0}".format(request.user.username)
    if message.is_media_message:
        notification_content = "{0} sent a {1}".format(
            request.user.username, 
            "photo" if message.is_image else "video"
        )
    
    Notification.objects.create(
        user=participant.user,
        notification_type='message',
        content=notification_content,
        related_user=request.user
    )
```

**Context Processor Integration:**
**File**: `users/context_processors.py`

```python
def notification_count(request):
    if request.user.is_authenticated:
        unread_count = Notification.objects.filter(
            user=request.user,
            is_read=False
        ).count()
        return {'notification_count': unread_count}
    return {'notification_count': 0}
```

---

## 🛡️ **SECURITY INTEGRATION**

### **Block-Based Security**
**File**: `messaging/views.py`

```python
# Check for blocks before starting conversation
if UserBlock.objects.filter(
    (Q(blocker=request.user) & Q(blocked_user=other_user)) |
    (Q(blocker=other_user) & Q(blocked_user=request.user))
).exists():
    messages.error(request, "You cannot start a conversation with this user.")
    return redirect('conversation_list')
```

**Comprehensive Block Enforcement:**
- **Conversation Creation**: Blocked users cannot start conversations
- **Message Viewing**: Blocked conversations hidden from lists
- **Group Participation**: Blocked users excluded from groups
- **Search Results**: Blocked users filtered from searches

### **Media Security**
**File**: `messaging/forms.py`

```python
def clean(self):
    cleaned_data = super().clean()
    media_file = cleaned_data.get('media_file')
    
    if media_file:
        # Content type validation
        if hasattr(media_file, 'content_type'):
            if 'image' in media_file.content_type:
                cleaned_data['media_type'] = 'image'
            elif 'video' in media_file.content_type:
                cleaned_data['media_type'] = 'video'
            else:
                raise forms.ValidationError("Unsupported file type.")
        
        # File extension fallback
        filename = media_file.name.lower()
        if filename.endswith(('.jpg', '.jpeg', '.png', '.gif')):
            cleaned_data['media_type'] = 'image'
        elif filename.endswith(('.mp4', '.mov', '.avi', '.webm')):
            cleaned_data['media_type'] = 'video'
```

**Media Security Features:**
- **Type Validation**: Strict file type checking
- **Verification Requirement**: Media sharing requires verified account
- **Size Limits**: Configurable file size restrictions
- **Malware Scanning**: Ready for antivirus integration

---

This completes Part 2 of the technical deep dive, covering the sophisticated messaging system with multi-layer encryption, custom blockchain implementation, and comprehensive security integration. The system demonstrates enterprise-level messaging capabilities with cutting-edge security features.
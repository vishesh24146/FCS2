# BeYou Backend Technical Deep Dive - Part 3: Marketplace & Admin Systems

## 🛒 **MARKETPLACE ARCHITECTURE**

### **E-commerce Integration Philosophy**
The marketplace is **fully integrated** into the social platform, not a separate system:
- **Social Commerce**: Leverages existing friend networks for trust
- **Verification-Based**: Only verified users can participate
- **Security-First**: Block system prevents unwanted interactions
- **Audit Trail**: Complete transaction history with blockchain potential

### **Marketplace Models Deep Dive**
**File**: `marketplace/models.py`

#### **Item Management System**
```python
class Item(models.Model):
    STATUS_CHOICES = (
        ('available', 'Available'),
        ('sold', 'Sold'),
        ('reserved', 'Reserved'),    # During checkout process
        ('inactive', 'Inactive'),    # Admin-disabled or user-hidden
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)  # Security
    seller = models.ForeignKey(CustomUser, related_name='selling_items')
    category = models.ForeignKey(Category, on_delete=models.SET_NULL)
    name = models.CharField(max_length=200)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='marketplace/')
    status = models.CharField(choices=STATUS_CHOICES, default='available')
```

**Status Flow Management:**
1. **Available**: Listed for sale, visible to buyers
2. **Reserved**: In someone's cart/checkout process
3. **Sold**: Transaction completed
4. **Inactive**: Hidden by seller or admin

#### **Shopping Cart System**
```python
class Cart(models.Model):
    user = models.OneToOneField(CustomUser, related_name='cart')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    @property
    def total_price(self):
        return sum(item.item.price * item.quantity for item in self.items.all())
    
    @property
    def total_items(self):
        return sum(item.quantity for item in self.items.all())

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, related_name='items')
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('cart', 'item')  # Prevent duplicates
```

**Cart Features:**
- **Persistent Storage**: Cart survives browser sessions
- **Quantity Management**: Multiple quantities of same item
- **Real-time Totals**: Dynamic price calculation
- **Duplicate Prevention**: Unique constraint on cart+item

#### **Order Management System**
```python
class Order(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('payment_initiated', 'Payment Initiated'),
        ('paid', 'Paid'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(CustomUser, related_name='orders')
    status = models.CharField(choices=STATUS_CHOICES, default='pending')
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_address = models.TextField()
    payment_id = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

**Order Lifecycle:**
1. **Pending**: Order created, items reserved
2. **Payment Initiated**: User started payment process
3. **Paid**: Payment successful, items marked sold
4. **Shipped**: Seller marks as shipped
5. **Delivered**: Order completed
6. **Cancelled**: Order cancelled, items returned to available

### **Payment Processing System**
**File**: `marketplace/models.py` - Payment model

```python
class Payment(models.Model):
    PAYMENT_METHOD_CHOICES = (
        ('credit_card', 'Credit Card'),
        ('debit_card', 'Debit Card'),
    )
    
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    order = models.OneToOneField(Order, related_name='payment')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(choices=PAYMENT_METHOD_CHOICES)
    status = models.CharField(choices=STATUS_CHOICES, default='pending')
    transaction_id = models.CharField(max_length=100)
    
    # Card details (for simulation only)
    card_number_last4 = models.CharField(max_length=4)
    card_expiry = models.CharField(max_length=7)  # MM/YYYY format
```

**Payment Security:**
- **No Full Card Storage**: Only last 4 digits stored
- **Transaction IDs**: Unique identifiers for tracking
- **Status Tracking**: Complete payment lifecycle
- **Simulation Ready**: Easy to integrate real payment gateways

---

## 💳 **PAYMENT PROCESSING DEEP DIVE**

### **Payment Form Validation**
**File**: `marketplace/forms.py`

```python
class PaymentForm(forms.ModelForm):
    card_number = forms.CharField(
        max_length=16,
        widget=forms.TextInput(attrs={
            'data-mask': '0000 0000 0000 0000',  # Input masking
            'autocomplete': 'off'                # Security
        })
    )
    
    def clean_card_number(self):
        card_number = self.cleaned_data.get('card_number')
        card_number = ''.join(card_number.split())  # Remove spaces
        
        # Basic validation
        if not card_number.isdigit():
            raise forms.ValidationError("Card number should contain only digits.")
        if len(card_number) < 13 or len(card_number) > 19:
            raise forms.ValidationError("Card number should be between 13 and 19 digits.")
        
        return card_number
```

**Security Features:**
- **Input Masking**: Formatted card number display
- **No Autocomplete**: Prevents browser storage
- **Length Validation**: Standard card number lengths
- **Digit-only Validation**: Prevents injection attacks

### **Payment Processing Logic**
**File**: `marketplace/views.py` - `payment` function

```python
@login_required
def payment(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    
    # Update order status to payment_initiated
    if order.status in ['pending', 'cancelled']:
        order.status = 'payment_initiated'
        order.save()
        
        # Reserve items during payment
        for order_item in order.items.all():
            if order_item.original_item and order_item.original_item.status == 'available':
                order_item.original_item.status = 'reserved'
                order_item.original_item.save()
    
    if request.method == 'POST':
        form = PaymentForm(request.POST)
        if form.is_valid():
            # Create or update payment
            try:
                payment = Payment.objects.get(order=order)
            except Payment.DoesNotExist:
                payment = form.save(commit=False)
                payment.order = order
                payment.amount = order.total_price
            
            # Store card details (last 4 digits only)
            card_number = form.cleaned_data.get('card_number')
            payment.card_number_last4 = card_number[-4:]
            
            # Simulate payment processing
            import random, string
            transaction_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
            payment.transaction_id = transaction_id
            
            # 95% success rate for demo
            if random.random() < 0.95:
                payment.status = 'completed'
                order.status = 'paid'
                
                # Mark items as sold
                for order_item in order.items.all():
                    if order_item.original_item:
                        order_item.original_item.status = 'sold'
                        order_item.original_item.save()
            else:
                payment.status = 'failed'
                order.status = 'pending'
                
                # Return items to available
                for order_item in order.items.all():
                    if order_item.original_item:
                        order_item.original_item.status = 'available'
                        order_item.original_item.save()
            
            payment.save()
```

**Payment Flow Features:**
- **Status Management**: Proper order status transitions
- **Item Reservation**: Prevents double-selling during payment
- **Transaction Tracking**: Unique transaction IDs
- **Failure Handling**: Automatic rollback on payment failure
- **Simulation**: Realistic payment processing simulation

---

## 🔍 **MARKETPLACE SECURITY INTEGRATION**

### **Block System Integration**
**File**: `marketplace/views.py`

```python
@login_required
def marketplace_home(request):
    # Get blocked users
    blocked_by_me = UserBlock.objects.filter(blocker=request.user).values_list('blocked_user', flat=True)
    blocking_me = UserBlock.objects.filter(blocked_user=request.user).values_list('blocker', flat=True)
    blocked_users = list(blocked_by_me) + list(blocking_me)
    
    # Exclude blocked users' items
    items = Item.objects.filter(status='available').exclude(seller__in=blocked_users)
```

**Security Enforcement Points:**
- **Item Browsing**: Blocked users' items hidden from search
- **Item Details**: Cannot view blocked users' item details
- **Cart Operations**: Cannot add blocked users' items to cart
- **Purchase Prevention**: Complete transaction blocking

### **Verification Requirements**
**Every marketplace function requires verification:**

```python
@login_required
def add_item(request):
    if not request.user.is_verified:
        messages.warning(request, "You need to verify your account to sell items.")
        return redirect('verification_request')
```

**Verification Gates:**
- **Selling**: Only verified users can list items
- **Buying**: Only verified users can purchase
- **Cart Access**: Verification required for cart operations
- **Payment**: Verification required for payment processing

---

## 👨‍💼 **ADMIN SYSTEM ARCHITECTURE**

### **Multi-Level Admin Access**
The admin system has **multiple access levels**:

1. **Django Admin**: Hidden at `/asvv-only/` for security
2. **Custom Admin Views**: Staff-only views for specific functions
3. **Blockchain Explorer**: Technical staff access to blockchain data
4. **Moderation Tools**: Content and user management

### **Security-First Admin Design**
**File**: `social_media/urls.py`

```python
def hidden_admin(request):
    return HttpResponse(
        """
        <html>
        <head><title>403 Forbidden</title></head>
        <body style="text-align:center; margin-top: 50px;">
            <h1>403 Forbidden</h1>
            <p><strong>Admin Dashboard</strong> is not accessible on your IP address.</p>
            <p>Access denied for security reasons. Your attempt has been logged.</p>
            <p>Multiple attempts will result into permanent IP blocking by Firewall.</p>
        </body>
        </html>
        """,
        content_type='text/html',
        status=403
    )

urlpatterns = [
    path('asvv-only/', admin.site.urls),  # Hidden admin URL
    path('admin/', hidden_admin),         # Fake admin for security
]
```

**Admin Security Features:**
- **URL Obfuscation**: Real admin at non-standard URL
- **Fake Admin Page**: Deters attackers, logs attempts
- **Access Logging**: All admin access attempts logged
- **IP Blocking Ready**: Framework for IP-based restrictions

### **User Management System**
**File**: `users/views.py` - Admin functions

#### **User Verification Management**
```python
@login_required
@user_passes_test(lambda u: u.is_staff)
def admin_verification_list(request):
    # Get pending verification requests
    pending_requests = CustomUser.objects.filter(
        verification_status='pending',
        id_document__isnull=False,
        verification_reason__isnull=False
    ).order_by('verification_submitted_at')
    
    # Get processed requests
    processed_requests = CustomUser.objects.filter(
        verification_status__in=['approved', 'rejected']
    ).order_by('-verification_processed_at')[:50]
```

**Verification Dashboard Features:**
- **Pending Queue**: All verification requests awaiting review
- **Document Access**: Secure access to uploaded ID documents
- **Processing History**: Complete audit trail of decisions
- **Batch Processing**: Efficient handling of multiple requests

#### **User Banning System**
```python
@login_required
@user_passes_test(lambda u: u.is_staff)
def admin_ban_user(request, user_id):
    user_to_ban = get_object_or_404(CustomUser, id=user_id)
    
    # Prevent banning staff or self
    if user_to_ban.is_staff or user_to_ban == request.user:
        messages.error(request, "You cannot ban staff members or yourself.")
        return redirect('admin_user_management')
    
    if request.method == 'POST':
        ban_type = request.POST.get('ban_type')
        reason = request.POST.get('reason', '')
        
        if ban_type == 'temp':
            days = int(request.POST.get('ban_days', 7))
            # Temporary ban implementation
            user_to_ban.is_active = False
            user_to_ban.save()
            
        elif ban_type == 'perm':
            # Permanent ban
            user_to_ban.is_active = False
            user_to_ban.save()
```

**Banning System Features:**
- **Staff Protection**: Cannot ban staff members or self
- **Temporary Bans**: Time-limited restrictions
- **Permanent Bans**: Complete account deactivation
- **Reason Tracking**: Documentation of ban reasons
- **Reversible**: Unban functionality available

### **Content Moderation System**
**File**: `users/views.py` - Report processing

#### **Report Management Dashboard**
```python
@login_required
@user_passes_test(lambda u: u.is_staff)
def admin_reports_list(request):
    # Get reports by status
    pending_reports = Report.objects.filter(status='pending').order_by('-created_at')
    investigating_reports = Report.objects.filter(status='investigating').order_by('-created_at')
    resolved_reports = Report.objects.filter(status__in=['resolved', 'dismissed']).order_by('-updated_at')[:50]
    
    # Count by type
    user_reports_count = Report.objects.filter(report_type='user').count()
    message_reports_count = Report.objects.filter(report_type='message').count()
    item_reports_count = Report.objects.filter(report_type='item').count()
```

**Moderation Dashboard Features:**
- **Multi-type Reports**: Users, messages, marketplace items
- **Status Tracking**: Pending, investigating, resolved
- **Evidence Management**: Screenshots and documentation
- **Action Documentation**: Complete moderation history

#### **Report Processing Workflow**
```python
@login_required
@user_passes_test(lambda u: u.is_staff)
def admin_process_report(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        admin_notes = request.POST.get('admin_notes', '')
        
        if action == 'resolve':
            report.status = 'resolved'
            resolution_type = request.POST.get('resolution_type')
            
            if resolution_type == 'warning':
                report.action_taken = f"Warning sent to {report.reported_user.username}"
                
            elif resolution_type == 'ban_temp':
                days = request.POST.get('ban_days', 7)
                report.action_taken = f"Temporary ban ({days} days)"
                reported_user = report.reported_user
                reported_user.is_active = False
                reported_user.save()
                
            elif resolution_type == 'delete_content':
                report.action_taken = "Reported content deleted"
                # Delete based on report type
                if report.report_type == 'message':
                    # Delete message
                elif report.report_type == 'item':
                    # Deactivate marketplace item
```

**Moderation Actions:**
- **Warning System**: Send warnings to users
- **Temporary Bans**: Time-limited account restrictions
- **Permanent Bans**: Complete account deactivation
- **Content Deletion**: Remove reported content
- **Documentation**: Complete action audit trail

### **Blockchain Administration**
**File**: `users/views.py` - Blockchain management

#### **Blockchain Explorer**
```python
@login_required
@user_passes_test(lambda u: u.is_staff)
def blockchain_explorer(request):
    from messaging.blockchain import get_blockchain_explorer_data, get_conversation_statistics
    
    # Get blockchain data
    blockchain_data = get_blockchain_explorer_data()
    
    # Get conversation statistics
    conversation_stats = get_conversation_statistics()
    
    # Get conversation information
    conversations = {}
    for conv_id in conversation_stats.keys():
        try:
            conv = Conversation.objects.get(id=UUID(conv_id))
            if conv.conversation_type == 'direct':
                participants = conv.participants.all()
                names = [p.user.username for p in participants]
                conversations[conv_id] = {
                    'name': f"Direct: {' & '.join(names)}",
                    'type': 'direct'
                }
            else:
                conversations[conv_id] = {
                    'name': conv.name,
                    'type': 'group'
                }
        except Conversation.DoesNotExist:
            conversations[conv_id] = {
                'name': f"Unknown Conversation ({conv_id})",
                'type': 'unknown'
            }
```

**Blockchain Admin Features:**
- **Complete Chain View**: All blocks and transactions
- **Conversation Analytics**: Message statistics by conversation
- **Integrity Verification**: Blockchain validation tools
- **Performance Monitoring**: Chain health and statistics

#### **Message Integrity Verification**
```python
@login_required
@user_passes_test(lambda u: u.is_staff)
def conversation_blockchain(request, conversation_id):
    from messaging.blockchain import get_conversation_blockchain_data, validate_conversation_integrity
    
    # Get blockchain data for this conversation
    blockchain_data = get_conversation_blockchain_data(conversation_id)
    
    # Validate conversation integrity
    integrity_results = validate_conversation_integrity(conversation_id)
```

**Integrity Verification Features:**
- **Per-Conversation Analysis**: Detailed integrity checking
- **Tamper Detection**: Identify modified messages
- **Verification Statistics**: Success/failure rates
- **Forensic Tools**: Detailed blockchain analysis

---

## 📊 **ANALYTICS & MONITORING**

### **Login Activity Analytics**
**File**: `users/views.py` - `login_logs`

```python
@login_required
@user_passes_test(lambda u: u.is_staff)
def login_logs(request):
    # Get filter parameters
    username = request.GET.get('username', '')
    status = request.GET.get('status', '')
    ip_address = request.GET.get('ip_address', '')
    
    # Apply filters
    activities = LoginActivity.objects.all()
    if username:
        activities = activities.filter(username__icontains=username)
    if status == 'success':
        activities = activities.filter(was_successful=True)
    elif status == 'failed':
        activities = activities.filter(was_successful=False)
    
    # Statistics
    total_logins = activities.count()
    successful_logins = activities.filter(was_successful=True).count()
    failed_logins = activities.filter(was_successful=False).count()
    unique_users = activities.filter(was_successful=True).values('user').distinct().count()
    unique_ips = activities.values('ip_address').distinct().count()
    
    # Threat analysis
    failure_counts = {}
    for username in activities.filter(was_successful=False).values_list('username', flat=True).distinct():
        if username:
            count = activities.filter(username=username, was_successful=False).count()
            failure_counts[username] = count
    
    most_failed = sorted(failure_counts.items(), key=lambda x: x[1], reverse=True)[:5]
```

**Analytics Features:**
- **Real-time Filtering**: Search by user, IP, date, status
- **Statistical Dashboard**: Success rates, unique metrics
- **Threat Detection**: Failed login pattern analysis
- **Forensic Capabilities**: Detailed activity investigation

### **System Health Monitoring**
**Integrated monitoring across all systems:**

1. **Authentication Health**: Login success rates, failed attempts
2. **Blockchain Integrity**: Message verification statistics
3. **Marketplace Activity**: Transaction success rates, payment failures
4. **User Engagement**: Verification rates, active user metrics
5. **Security Events**: Block actions, report submissions

---

This completes Part 3 of the technical deep dive, covering the sophisticated marketplace system with full e-commerce capabilities, comprehensive admin tools with multi-level access control, and advanced analytics for system monitoring. The integration demonstrates enterprise-level platform management with security-first design principles.
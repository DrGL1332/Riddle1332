#!/usr/bin/env python3
"""
Dr.GL Image Verification Tool
Verifies the cryptographic signature of Dr.GL puzzle images.

Usage: python3 verify_drgl_image.py <image_file.png>
"""

import sys
import base64
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import io

def verify_image(image_path):
    """Verify Dr.GL image signature"""
    
    print(f"🔍 Verifying: {image_path}")
    print("-" * 60)
    
    try:
        # Load image
        img = Image.open(image_path)
        
        # Check format
        if img.format != 'PNG':
            print(f"❌ ERROR: File is {img.format}, not PNG")
            print("   Dr.GL images must be PNG format.")
            return False
        
        # Check metadata
        if 'Author' not in img.info:
            print("❌ ERROR: Missing 'Author' metadata")
            print("   This is not a signed Dr.GL image.")
            return False
            
        if img.info['Author'] != 'Dr.GL':
            print(f"❌ ERROR: Author is '{img.info['Author']}', not 'Dr.GL'")
            return False
        
        # Get metadata
        contact = img.info.get('Contact', 'N/A')
        signature_b64 = img.info.get('Signature', '')
        public_key_pem = img.info.get('PublicKey', '')
        algorithm = img.info.get('SignatureAlgorithm', 'N/A')
        
        print(f"✅ Author: {img.info['Author']}")
        print(f"✅ Contact: {contact}")
        print(f"✅ Algorithm: {algorithm}")
        
        # Verify signature exists
        if not signature_b64 or not public_key_pem:
            print("❌ ERROR: Missing signature or public key")
            return False
        
        # Decode signature
        try:
            signature = base64.b64decode(signature_b64)
        except Exception as e:
            print(f"❌ ERROR: Invalid signature encoding: {e}")
            return False
        
        # Load public key
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('ascii'),
                backend=default_backend()
            )
        except Exception as e:
            print(f"❌ ERROR: Invalid public key: {e}")
            return False
        
        # Get image data (recreate the exact data that was signed)
        buffer = io.BytesIO()
        img_copy = img.copy()
        img_copy.save(buffer, format='PNG')
        image_data = buffer.getvalue()
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                image_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("\n🎉 SIGNATURE VERIFIED!")
            print("✅ This is an AUTHENTIC Dr.GL image.")
            print("✅ Image has not been modified.")
            return True
            
        except Exception as e:
            print(f"\n❌ SIGNATURE VERIFICATION FAILED!")
            print(f"   This image has been modified or is not authentic.")
            print(f"   Detail: {type(e).__name__}")
            return False
            
    except FileNotFoundError:
        print(f"❌ ERROR: File not found: {image_path}")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 verify_drgl_image.py <image_file.png>")
        print("\nExample:")
        print("  python3 verify_drgl_image.py DrGL_FINAL_English.png")
        print("\nThis script verifies that an image was signed by Dr.GL")
        print("and has not been modified since signing.")
        sys.exit(1)
    
    image_path = sys.argv[1]
    result = verify_image(image_path)
    sys.exit(0 if result else 1)

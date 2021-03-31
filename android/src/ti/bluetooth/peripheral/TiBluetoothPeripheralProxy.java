package ti.bluetooth.peripheral;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.ScanRecord;
import android.content.Context;
import android.os.ParcelUuid;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.common.Log;
import org.appcelerator.titanium.TiBlob;
import ti.bluetooth.TiBluetoothModule;
import ti.bluetooth.gatt.TiBluetoothCharacteristicProxy;
import ti.bluetooth.gatt.TiBluetoothServiceProxy;
import ti.bluetooth.listener.OnPeripheralConnectionStateChangedListener;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.net.URLEncoder;



@Kroll.proxy(parentModule = TiBluetoothModule.class)
public class TiBluetoothPeripheralProxy extends KrollProxy {
  private static final String DID_DISCOVER_SERVICES = "didDiscoverServices";
  private static final String DID_DISCOVER_CHARACTERISTICS_FOR_SERVICE =
      "didDiscoverCharacteristicsForService";
  private static final String DID_UPDATE_VALUE_FOR_CHARACTERISTIC =
      "didUpdateValueForCharacteristic";
  private static final String DID_WRITE_VALUE_FOR_CHARACTERISTIC =
      "didWriteValueForCharacteristic";
  private static final String DID_READ_VALUE_FOR_CHARACTERISTIC =
      "didReadValueForCharacteristic";
  private static final String SERVICE_KEY = "service";

  private BluetoothDevice bluetoothDevice;
  private BluetoothGatt bluetoothGatt;
  private List<TiBluetoothServiceProxy> services;
  private ScanRecord scanRecord;

  public TiBluetoothPeripheralProxy(BluetoothDevice bluetoothDevice,
                                    ScanRecord scanRecord) {
    this.bluetoothDevice = bluetoothDevice;
    this.scanRecord = scanRecord;
  }

  public void
  connectPeripheral(Context context, final boolean notifyOnConnection,
                    final boolean notifyOnDisconnection,
                    final OnPeripheralConnectionStateChangedListener
                        onPeripheralConnectionStateChangedListener) {
    bluetoothDevice.connectGatt(context, false, new BluetoothGattCallback() {
      @Override
      public void onConnectionStateChange(BluetoothGatt gatt, int status,
                                          int newState) {
        super.onConnectionStateChange(gatt, status, newState);

        if (status == BluetoothGatt.GATT_SUCCESS) {
          Log.i("[INFO] TiBluetoothPeripheralProxy connectPeripheral()", "GATT_SUCCESS");
          if (newState == BluetoothProfile.STATE_CONNECTED) {
            Log.i("[INFO] TiBluetoothPeripheralProxy connectPeripheral()", "CONNECTED");
            bluetoothGatt = gatt;
            if (notifyOnConnection) {
              onPeripheralConnectionStateChangedListener
                  .onPeripheralConnectionStateConnected(
                      TiBluetoothPeripheralProxy.this);
            }
          } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
            Log.i("[INFO] TiBluetoothPeripheralProxy connectPeripheral()", "DISCONNECTED");
            if (notifyOnDisconnection) {
              onPeripheralConnectionStateChangedListener
                  .onPeripheralConnectionStateDisconnected(
                      TiBluetoothPeripheralProxy.this);
            }
          }
        } else {
          Log.i("[INFO] TiBluetoothPeripheralProxy connectPeripheral()", "GATT_ERROR");
          onPeripheralConnectionStateChangedListener
              .onPeripheralConnectionStateError(
                  TiBluetoothPeripheralProxy.this);
        }
      }

      @Override
      public void onServicesDiscovered(BluetoothGatt gatt, int status) {
        super.onServicesDiscovered(gatt, status);

        services = mapServices(gatt.getServices());
        bluetoothGatt = gatt;

        firePeripheralEvent(DID_DISCOVER_SERVICES,
                            TiBluetoothPeripheralProxy.this, null, null);
      }

      @Override
      public void onCharacteristicWrite(
          BluetoothGatt gatt, BluetoothGattCharacteristic characteristic,
          int status) {
        super.onCharacteristicWrite(gatt, characteristic, status);

        firePeripheralEvent(DID_WRITE_VALUE_FOR_CHARACTERISTIC,
                            TiBluetoothPeripheralProxy.this, null,
                            new TiBluetoothCharacteristicProxy(characteristic));
      }

      @Override
      public void onCharacteristicRead(
          BluetoothGatt gatt, BluetoothGattCharacteristic characteristic,
          int status) {
        super.onCharacteristicRead(gatt, characteristic, status);

        firePeripheralEvent(DID_READ_VALUE_FOR_CHARACTERISTIC,
                            TiBluetoothPeripheralProxy.this, null,
                            new TiBluetoothCharacteristicProxy(characteristic));
      }

      @Override
      public void onCharacteristicChanged(
          BluetoothGatt gatt,
          final BluetoothGattCharacteristic characteristic) {
        super.onCharacteristicChanged(gatt, characteristic);

        firePeripheralEvent(DID_UPDATE_VALUE_FOR_CHARACTERISTIC,
                            TiBluetoothPeripheralProxy.this, null,
                            new TiBluetoothCharacteristicProxy(characteristic));
      }
    });
  }

  public void disconnectPeripheral() {
    bluetoothGatt.disconnect();
    bluetoothGatt.close();
  }

  private List<TiBluetoothServiceProxy>
  mapServices(List<BluetoothGattService> services) {
    List<TiBluetoothServiceProxy> tiBluetoothServiceProxies = new ArrayList<>();

    for (BluetoothGattService bluetoothGatt : services) {
      tiBluetoothServiceProxies.add(new TiBluetoothServiceProxy(bluetoothGatt));
    }

    return tiBluetoothServiceProxies;
  }

  private void
  firePeripheralEvent(String event,
                      TiBluetoothPeripheralProxy bluetoothPeripheral,
                      TiBluetoothServiceProxy service,
                      TiBluetoothCharacteristicProxy characteristic) {
    KrollDict kd = new KrollDict();
    kd.put("peripheral", bluetoothPeripheral);
    kd.put("service", service);
    kd.put("characteristic", characteristic);

    fireEvent(event, kd);
  }

  @Kroll.method
  public void discoverServices() {
    bluetoothGatt.discoverServices();
  }

  @Kroll.method
  public void discoverCharacteristicsForService(KrollDict args) {
    TiBluetoothServiceProxy service =
        (TiBluetoothServiceProxy)args.get(SERVICE_KEY);

    if (service.getCharacteristics().length > 0) {
      firePeripheralEvent(DID_DISCOVER_CHARACTERISTICS_FOR_SERVICE, this,
                          service, null);
    }
  }

  @Kroll.getProperty
  @Kroll.method
  public String getName() {
    return bluetoothDevice.getName();
  }

  @Kroll.getProperty
  @Kroll.method
  public String getAddress() {
    return bluetoothDevice.getAddress();
  }

  @Kroll.getProperty
  @Kroll.method
  public KrollDict getUuids() {
    ParcelUuid[] uuids = bluetoothDevice.getUuids();
    KrollDict out = new KrollDict();
    if (uuids != null) {
      for (int i = 0; i < uuids.length; i++) {
        out.put("uuid", uuids[i].toString());
      }
    } else {
      Map<ParcelUuid, byte[]> data = scanRecord.getServiceData();
      for (ParcelUuid key : data.keySet()) {
        out.put("uuid", key.toString());
      }
    }
    return out;
  }

  @Kroll.getProperty
  @Kroll.method
  public Object[] getServices() {
    return services.toArray();
  }

  @Kroll.method
  public void setNotifyValueForCharacteristic(
      boolean enabled, TiBluetoothCharacteristicProxy characteristic) {
    bluetoothGatt.setCharacteristicNotification(
        characteristic.getCharacteristic(), enabled);
  }


  @Kroll.method
  public void readValueForCharacteristic(TiBluetoothCharacteristicProxy characteristic) {
    bluetoothGatt.readCharacteristic(characteristic.getCharacteristic());
  }


  @Kroll.method
  public void writeValueForCharacteristicWithType(
      String value,
      TiBluetoothCharacteristicProxy tiBluetoothCharacteristicProxy,
      int writeType,
      String aesKey) {
    BluetoothGattCharacteristic characteristic =
        tiBluetoothCharacteristicProxy.getCharacteristic();


//Log.i("[INFO] TiBluetoothModule", "writeValueForCharacteristicWithType: key=>"+aesKey);
//Log.i("[INFO] TiBluetoothModule", "writeValueForCharacteristicWithType: value=>"+value);

    if( aesKey != null && !aesKey.isEmpty()) {
    
      try{
        byte[] encBytes = encrypt(value, aesKey);
        characteristic.setValue(encBytes);
      } catch (Exception e) {
          e.printStackTrace();
          Log.w("[WARN] TiBluetoothModule 1 exception: ", e.toString());
      }
    } else {
      try{
        byte[] bytes = HexStringToByteArray(value);
        String st = new String(bytes, "UTF-8");
        Log.w("[WARN] TiBluetoothModule: ", st);
        characteristic.setValue(bytes);
        
      } catch (Exception e) {
          e.printStackTrace();
          Log.w("[WARN] TiBluetoothModule 2 exception: ", e.toString());
      }
    }   
    characteristic.setWriteType(writeType);
    if(!bluetoothGatt.writeCharacteristic(characteristic)){
      Log.w("[WARN] TiBluetoothModule", "Couldn't write characteristic");
    }
  }

/**
     * Utility method to convert a byte array to a hexadecimal string.
     *
     * @param bytes Bytes to convert
     * @return String, containing hexadecimal representation.
     */
    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2]; // Each byte has two hex characters (nibbles)
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // Cast bytes[j] to int, treating as unsigned value
            hexChars[j * 2] = hexArray[v >>> 4]; // Select hex character from upper nibble
            hexChars[j * 2 + 1] = hexArray[v & 0x0F]; // Select hex character from lower nibble
        }
        return new String(hexChars);
    }
    /**
     * Utility method to convert a hexadecimal string to a byte string.
     *
     * <p>Behavior with input strings containing non-hexadecimal characters is undefined.
     *
     * @param s String containing hexadecimal characters to convert
     * @return Byte array generated from input
     * @throws java.lang.IllegalArgumentException if input length is incorrect
     */
    public static byte[] HexStringToByteArray(String s) throws IllegalArgumentException {
        int len = s.length();
        if (len % 2 == 1) {
            throw new IllegalArgumentException("Hex string must have even number of characters");
        }
        byte[] data = new byte[len / 2]; // Allocate 1 byte per 2 hex characters
        for (int i = 0; i < len; i += 2) {
            // Convert each character into a integer (base-16), then bit-shift into place
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }



      public static byte[] encrypt(String plainText, String key) throws Exception {
        byte[] clean = HexStringToByteArray(plainText); //plainText.getBytes();


        SecretKeySpec secretKeySpec = new SecretKeySpec(HexStringToByteArray(key), "AES");


        // Generating IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Hashing key.
        // MessageDigest digest = MessageDigest.getInstance("SHA-256");
        // digest.update(HexStringToByteArray(key)); //key.getBytes("UTF-8"));
        // byte[] keyBytes = new byte[16];
        // System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        // SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

        Log.w("[WARN] TiBluetoothModule", "Encrypt ended");
        String st = ByteArrayToHexString(encryptedIVAndText);
        Log.w("[WARN] TiBluetoothModule encryptedIVAndText", st);

        String dec = decrypt(encryptedIVAndText, key);
Log.w("[WARN] TiBluetoothModule dec", dec);

        return encryptedIVAndText;
      }

      public static String decrypt(byte[] encryptedIvTextBytes, String key) throws Exception {
        int ivSize = 16;
        int keySize = 16;

        // Extract IV.
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Extract encrypted part.
        int encryptedSize = encryptedIvTextBytes.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

        // Hash key.
        // byte[] keyBytes = new byte[keySize];
        // MessageDigest md = MessageDigest.getInstance("SHA-256");
        // md.update(key.getBytes());
        // System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
        // SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(HexStringToByteArray(key), "AES");      

        // Decrypt.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        return new String(decrypted);
      }  
}

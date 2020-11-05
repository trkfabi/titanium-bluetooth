/**
 * Appcelerator Titanium Mobile
 * Copyright (c) 2009-2016 by Appcelerator, Inc. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */

#import "TiBluetoothPeripheralProxy.h"
#import "TiBluetoothCharacteristicProvider.h"
#import "TiBluetoothCharacteristicProxy.h"
#import "TiBluetoothDescriptorProxy.h"
#import "TiBluetoothPeripheralProvider.h"
#import "TiBluetoothServiceProxy.h"
#import "TiBluetoothUtils.h"
#import "TiUtils.h"
#import "TiBlob.h"
#import "TiBluetoothL2CAPChannelProxy.h"

@implementation TiBluetoothPeripheralProxy

- (id)_initWithPageContext:(id<TiEvaluator>)context andPeripheral:(CBPeripheral *)__peripheral
{
  if ([super _initWithPageContext:[self pageContext]]) {
    _peripheral = __peripheral;
    [_peripheral setDelegate:self];
  }

  return self;
}

- (CBPeripheral *)peripheral
{
  return _peripheral;
}

#pragma mark Public API's

- (NSString *)name
{
  return _peripheral.name;
}

- (NSNumber *)rssi
{
  DEPRECATED_REMOVED(@"Bluetooth.Peripheral.rssi (use \"didReadRSSI\" event instead)", @"2.0.0", @"2.0.0");
  return @(-1);
}

- (NSNumber *)state
{
  return @(_peripheral.state);
}

- (NSArray *)services
{
  return [self arrayFromServices:_peripheral.services];
}

- (NSString *)identifier
{
  return _peripheral.identifier.UUIDString;
}

- (void)readRSSI:(id)unused
{
  [_peripheral readRSSI];
}

- (void)discoverServices:(id)args
{
  [_peripheral discoverServices:[TiBluetoothUtils CBUUIDArrayFromStringArray:args]];
}

- (void)discoverIncludedServicesForService:(id)args
{
  ENSURE_ARG_COUNT(args, 2);

  id includedServices = [args objectAtIndex:0];
  id service = [args objectAtIndex:1];

  ENSURE_TYPE(includedServices, NSArray);
  ENSURE_TYPE(service, TiBluetoothServiceProxy);

  [_peripheral discoverIncludedServices:[TiBluetoothUtils CBUUIDArrayFromStringArray:includedServices]
                             forService:[(TiBluetoothServiceProxy *)service service]];
}

- (void)discoverCharacteristicsForService:(id)args
{
  // Deprecated, requires the first arg to be set or null'd
  if ([args count] == 2) {
    NSLog(@"[WARN] Using discoverCharacteristicsForService with two arguments is deprecated. Use it with an object of keys instead. Example:");
    NSLog(@"[WARN] \tdiscoverCharacteristicsForService({\n\t\tcharacteristics: ['<uuid>', '<uuid>'],\n\t\tservice: myService\n\t})")

        id characteristics
        = [args objectAtIndex:0];
    id service = [args objectAtIndex:1];

    ENSURE_TYPE_OR_NIL(characteristics, NSArray);
    ENSURE_TYPE(service, TiBluetoothServiceProxy);

    [_peripheral discoverCharacteristics:[TiBluetoothUtils CBUUIDArrayFromStringArray:characteristics]
                              forService:[(TiBluetoothServiceProxy *)service service]];
  } else {
    ENSURE_SINGLE_ARG(args, NSDictionary);

    id characteristics = [args objectForKey:@"characteristics"];
    id service = [args objectForKey:@"service"];

    ENSURE_TYPE_OR_NIL(characteristics, NSArray);
    ENSURE_TYPE(service, TiBluetoothServiceProxy);

    [_peripheral discoverCharacteristics:[TiBluetoothUtils CBUUIDArrayFromStringArray:characteristics]
                              forService:[(TiBluetoothServiceProxy *)service service]];
  }
}

- (void)readValueForCharacteristic:(id)value
{
  ENSURE_SINGLE_ARG(value, TiBluetoothCharacteristicProxy);

  [_peripheral readValueForCharacteristic:[(TiBluetoothCharacteristicProxy *)value characteristic]];
}

- (NSNumber *)maximumWriteValueLengthForType:(id)value
{
  return NUMUINTEGER([_peripheral maximumWriteValueLengthForType:[TiUtils intValue:value]]);
}

- (void)writeValueForCharacteristicWithType:(id)args
{
  ENSURE_ARG_COUNT(args, 3);

  id value = [args objectAtIndex:0];
  id characteristic = [args objectAtIndex:1];
  id type = [args objectAtIndex:2];

  //ENSURE_TYPE(value, TiBlob);
  ENSURE_TYPE(characteristic, TiBluetoothCharacteristicProxy);
  ENSURE_TYPE(type, NSNumber);

  //[_peripheral writeValue:[(TiBlob *)value data]
    NSData *dataValue = [self dataFromHexString:value];

    [_peripheral writeValue:dataValue
        forCharacteristic:[(TiBluetoothCharacteristicProxy *)characteristic characteristic]
                     type:[TiUtils intValue:type]];
}

-(NSData *)dataFromHexString:(NSString *)string
{
    string = [string lowercaseString];
    NSMutableData *data= [NSMutableData new];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i = 0;
    int length = string.length;
    while (i < length-1) {
        char c = [string characterAtIndex:i++];
        if (c < '0' || (c > '9' && c < 'a') || c > 'f')
            continue;
        byte_chars[0] = c;
        byte_chars[1] = [string characterAtIndex:i++];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}

- (NSNumber *)canSendWriteWithoutResponse
{
  return NUMBOOL([_peripheral canSendWriteWithoutResponse]);
}

//- (void)openL2CAPChannel:(id)args
- (void)openL2CAPChannel:(id)psm
{
  //ENSURE_SINGLE_ARG(args, NSDictionary);
  //[_peripheral openL2CAPChannel:0];
    ENSURE_SINGLE_ARG(psm, NSNumber);

    NSLog(@"[INFO] openL2CAPChannel %d", [TiUtils intValue:psm]);
    [_peripheral openL2CAPChannel:[TiUtils intValue:psm]];

}

- (void)setNotifyValueForCharacteristic:(id)args
{
  ENSURE_ARG_COUNT(args, 2);

  id notifyValue = [args objectAtIndex:0];
  id characteristic = [args objectAtIndex:1];

  ENSURE_TYPE(notifyValue, NSNumber);
  ENSURE_TYPE(characteristic, TiBluetoothCharacteristicProxy);

  [_peripheral setNotifyValue:[TiUtils boolValue:notifyValue]
            forCharacteristic:[(TiBluetoothCharacteristicProxy *)characteristic characteristic]];
}

- (void)discoverDescriptorsForCharacteristic:(id)value
{
  ENSURE_SINGLE_ARG(value, TiBluetoothCharacteristicProxy);

  [_peripheral discoverDescriptorsForCharacteristic:[(TiBluetoothCharacteristicProxy *)value characteristic]];
}

- (void)readValueForDescriptor:(id)value
{
  ENSURE_SINGLE_ARG(value, TiBluetoothDescriptorProxy);

  [_peripheral readValueForDescriptor:[(TiBluetoothDescriptorProxy *)value descriptor]];
}

- (void)writeValueForDescriptor:(id)args
{
  ENSURE_ARG_COUNT(args, 2);

  id value = [args objectAtIndex:0];
  id descriptor = [args objectAtIndex:1];

  ENSURE_TYPE(value, TiBlob);
  ENSURE_TYPE(descriptor, TiBluetoothDescriptorProxy);

  [_peripheral writeValue:[(TiBlob *)value data]
            forDescriptor:[(TiBluetoothDescriptorProxy *)descriptor descriptor]];
}

#pragma mark Peripheral Delegates

- (void)peripheralIsReadyToSendWriteWithoutResponse:(CBPeripheral *)peripheral
{
  if ([self _hasListeners:@"isReadyToSendWriteWithoutResponse"]) {
    [self fireEvent:@"isReadyToSendWriteWithoutResponse"
         withObject:@{
           @"peripheral" : [self peripheralProxyFromPeripheral:peripheral],
         }];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral didOpenL2CAPChannel:(CBL2CAPChannel *)channel error:(NSError *)error
{
  if ([self _hasListeners:@"didOpenL2CAPChannel"]) {
    [self fireEvent:@"didOpenL2CAPChannel"
         withObject:@{
           @"channel" : [[TiBluetoothL2CAPChannelProxy alloc] _initWithPageContext:[self pageContext] andChannel:channel],
           @"error" : NULL_IF_NIL(error.localizedDescription)
         }];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error
{
  if ([self _hasListeners:@"didDiscoverServices"]) {
    [self fireEvent:@"didDiscoverServices"
         withObject:@{
           @"peripheral" : [self peripheralProxyFromPeripheral:peripheral],
           @"error" : NULL_IF_NIL([error localizedDescription])
         }];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral didReadRSSI:(NSNumber *)RSSI error:(NSError *)error
{
  if ([self _hasListeners:@"didReadRSSI"]) {
    [self fireEvent:@"didReadRSSI"
         withObject:@{
           @"rssi" : RSSI,
           @"error" : NULL_IF_NIL([error localizedDescription])
         }];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral didUpdateNotificationStateForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error
{
  if ([self _hasListeners:@"didUpdateNotificationStateForCharacteristic"]) {
    [self fireEvent:@"didUpdateNotificationStateForCharacteristic"
         withObject:@{
           @"characteristic" : [self characteristicProxyFromCharacteristic:characteristic],
           @"error" : NULL_IF_NIL([error localizedDescription])
         }];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverCharacteristicsForService:(CBService *)service error:(NSError *)error
{
  if ([self _hasListeners:@"didDiscoverCharacteristicsForService"]) {
    [self fireEvent:@"didDiscoverCharacteristicsForService"
         withObject:@{
           @"peripheral" : [self peripheralProxyFromPeripheral:peripheral],
           @"service" : [[TiBluetoothServiceProxy alloc] _initWithPageContext:[self pageContext] andService:service],
           @"error" : NULL_IF_NIL([error localizedDescription])
         }];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error
{
  if ([self _hasListeners:@"didUpdateValueForCharacteristic"]) {
    [self fireEvent:@"didUpdateValueForCharacteristic"
         withObject:@{
           @"peripheral" : [self peripheralProxyFromPeripheral:peripheral],
           @"characteristic" : [self characteristicProxyFromCharacteristic:characteristic],
           @"error" : NULL_IF_NIL([error localizedDescription])
         }];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral didWriteValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error
{
  if ([self _hasListeners:@"didWriteValueForCharacteristic"]) {
    [self fireEvent:@"didWriteValueForCharacteristic"
         withObject:@{
           @"peripheral" : [self peripheralProxyFromPeripheral:peripheral],
           @"characteristic" : [self characteristicProxyFromCharacteristic:characteristic],
           @"error" : NULL_IF_NIL([error localizedDescription])
         }];
  }
}

#pragma mark Utilities

- (TiBluetoothPeripheralProxy *)peripheralProxyFromPeripheral:(CBPeripheral *)peripheral
{
  __block TiBluetoothPeripheralProxy *result = [[TiBluetoothPeripheralProvider sharedInstance] peripheralProxyFromPeripheral:peripheral];

  if (!result) {
    NSLog(@"[DEBUG] Could not find cached instance of Ti.Bluetooth.Peripheral proxy. Adding and returning it now.");

    result = [[TiBluetoothPeripheralProxy alloc] _initWithPageContext:[self pageContext] andPeripheral:peripheral];
    [[TiBluetoothPeripheralProvider sharedInstance] addPeripheral:result];
  }

  return result;
}

- (TiBluetoothCharacteristicProxy *)characteristicProxyFromCharacteristic:(CBCharacteristic *)characteristic
{
  __block TiBluetoothCharacteristicProxy *result = [[TiBluetoothCharacteristicProvider sharedInstance] characteristicProxyFromCharacteristic:characteristic];

  if (!result) {
    NSLog(@"[DEBUG] Could not find cached instance of Ti.Bluetooth.Characteristic proxy. Adding and returning it now.");

    result = [[TiBluetoothCharacteristicProxy alloc] _initWithPageContext:[self pageContext] andCharacteristic:characteristic];
    [[TiBluetoothCharacteristicProvider sharedInstance] addCharacteristic:result];
  }

  return result;
}

- (NSArray *)arrayFromServices:(NSArray<CBService *> *)services
{
  NSMutableArray *result = [NSMutableArray array];

  for (CBService *service in services) {
    [result addObject:[[TiBluetoothServiceProxy alloc] _initWithPageContext:[self pageContext] andService:service]];
  }

  return result;
}

@end

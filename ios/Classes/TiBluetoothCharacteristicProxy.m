/**
 * Appcelerator Titanium Mobile
 * Copyright (c) 2009-2016 by Appcelerator, Inc. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */

#import "TiBluetoothCharacteristicProxy.h"
#import "TiBlob.h"
#import "TiBluetoothDescriptorProxy.h"
#import "TiBluetoothServiceProxy.h"
#import "TiUtils.h"

@implementation TiBluetoothCharacteristicProxy

- (id)_initWithPageContext:(id<TiEvaluator>)context andCharacteristic:(CBCharacteristic *)_characteristic
{
  if ([super _initWithPageContext:[self pageContext]]) {
    characteristic = _characteristic;
  }

  return self;
}

- (id)_initWithPageContext:(id<TiEvaluator>)context andProperties:(id)args
{
  if (self = [super _initWithPageContext:context]) {
    id uuid = [args objectForKey:@"uuid"];
    id properties = [args objectForKey:@"properties"];
    id value = [args objectForKey:@"value"];
    id permissions = [args objectForKey:@"permissions"];

    characteristic = [[CBMutableCharacteristic alloc] initWithType:[CBUUID UUIDWithString:[TiUtils stringValue:uuid]]
                                                        properties:[TiUtils intValue:properties]
                                                             value:[(TiBlob *)value data]
                                                       permissions:[TiUtils intValue:permissions]];
  }

  return self;
}

- (CBCharacteristic *)characteristic
{
  return characteristic;
}

#pragma mark Public API's

- (TiBluetoothServiceProxy *)service
{
  return [[TiBluetoothServiceProxy alloc] _initWithPageContext:[self pageContext] andService:characteristic.service];
}

- (NSNumber *)properties
{
  return NUMUINTEGER(characteristic.properties);
}

- (NSNumber *)isNotifying
{
  return NUMBOOL(characteristic.isNotifying);
}

- (NSArray *)descriptors
{
  return [self arrayFromDescriptors:characteristic.descriptors];
}

- (NSString *)value
{
  //return [[TiBlob alloc] initWithData:characteristic.value mimetype:@"text/plain"];
    return [self hex:characteristic.value];

}

- (NSString *)uuid
{
  return characteristic.UUID.UUIDString;
}

#pragma mark Utilities
-(NSString*)hex:(NSData*)data{
     NSMutableData *result = [NSMutableData dataWithLength:2*data.length];
     unsigned const char* src = data.bytes;
     unsigned char* dst = result.mutableBytes;
     unsigned char t0, t1;

     for (int i = 0; i < data.length; i ++ ) {
          t0 = src[i] >> 4;
          t1 = src[i] & 0x0F;

          dst[i*2] = 48 + t0 + (t0 / 10) * 39;
          dst[i*2+1] = 48 + t1 + (t1 / 10) * 39;
     }

     return [[NSString alloc] initWithData:result encoding:NSASCIIStringEncoding];
}


- (NSArray *)arrayFromDescriptors:(NSArray<CBDescriptor *> *)descriptors
{
  NSMutableArray *result = [NSMutableArray array];

  for (CBDescriptor *descriptor in descriptors) {
    [result addObject:[[TiBluetoothDescriptorProxy alloc] _initWithPageContext:[self pageContext] andDescriptor:descriptor]];
  }

  return result;
}

@end

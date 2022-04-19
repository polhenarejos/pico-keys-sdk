/* 
 * This file is part of the Pico CCID distribution (https://github.com/polhenarejos/pico-ccid).
 * Copyright (c) 2022 Pol Henarejos.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CCID_H_
#define _CCID_H_

struct ccid_class_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdCCID;
	uint8_t  bMaxSlotIndex;
	uint8_t  bVoltageSupport;
	uint32_t dwProtocols;
	uint32_t dwDefaultClock;
	uint32_t dwMaximumClock;
	uint8_t  bNumClockSupport;
	uint32_t dwDataRate;
	uint32_t dwMaxDataRate;
	uint8_t  bNumDataRatesSupported;
	uint32_t dwMaxIFSD;
	uint32_t dwSynchProtocols;
	uint32_t dwMechanical;
	uint32_t dwFeatures;
	uint32_t dwMaxCCIDMessageLength;
	uint8_t  bClassGetResponse;
	uint8_t  bclassEnvelope;
	uint16_t wLcdLayout;
	uint8_t  bPINSupport;
	uint8_t  bMaxCCIDBusySlots;
} __attribute__ ((__packed__));

static const struct ccid_class_descriptor desc_ccid = {
    .bLength                = sizeof(struct ccid_class_descriptor),
    .bDescriptorType        = 0x21,
    .bcdCCID                = (0x0110),
    .bMaxSlotIndex          = 0,
    .bVoltageSupport        = 0x01,  // 5.0V
    .dwProtocols            = (
                              0x01|  // T=0
                              0x02), // T=1
    .dwDefaultClock         = (0xDFC),
    .dwMaximumClock         = (0xDFC),
    .bNumClockSupport       = 0,
    .dwDataRate             = (0x2580),
    .dwMaxDataRate          = (0x2580),
    .bNumDataRatesSupported = 0,
    .dwMaxIFSD              = (0xFE), // IFSD is handled by the real reader driver
    .dwSynchProtocols       = (0),
    .dwMechanical           = (0),
    .dwFeatures             = 0x40840, //USB-ICC, short & extended APDU
    .dwMaxCCIDMessageLength = 65544+10,
    .bClassGetResponse      = 0xFF,
    .bclassEnvelope         = 0xFF,
    .wLcdLayout             = 0x0,
    .bPINSupport            = 0x0,
    .bMaxCCIDBusySlots      = 0x01,
};

#endif
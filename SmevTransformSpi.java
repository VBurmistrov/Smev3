package ru.alfabank.ccjava.trustcore.smev3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Stack;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * Класс, реализующий алгоритм трансформации "urn://smev-gov-ru/xmldsig/transform" для Apache
 * Santuario.
 * 
 * Методические рекомендации по работе с ЕСМЭВ версия 3.4.0.3 
 * https://smev3.gosuslugi.ru/portal/
 * 
 * @author dpryakhin с редакциями VBurmistrov
 * 
 *         (https://github.com/MaksimOK/smev3cxf/blob/master/client_1.11/crypto/src/main/java/ru/
 *         voskhod/crypto/impl/SmevTransformSpi.java)
 * 
 */
public class SmevTransformSpi extends TransformSpi {
    
    private static final String NS_PREFIX = "ns";
    public static final String ALGORITHM_URN = "urn://smev-gov-ru/xmldsig/transform";
    private static final String ENCODING_UTF_8 = "UTF-8";
    
    private static Logger logger = LoggerFactory.getLogger(WrongSmevTransformSpi.class);
    private static AttributeSortingComparator attributeSortingComparator =
            new AttributeSortingComparator();
    
    private static ThreadLocal<XMLInputFactory> inputFactory =
            new ThreadLocal<XMLInputFactory>() {
                
                @Override
                protected XMLInputFactory initialValue() {
                    return XMLInputFactory.newInstance();
                }
            };
    
    private static ThreadLocal<XMLOutputFactory> outputFactory =
            new ThreadLocal<XMLOutputFactory>() {
                
                @Override
                protected XMLOutputFactory initialValue() {
                    return XMLOutputFactory.newInstance();
                }
            };
    
    private static ThreadLocal<XMLEventFactory> eventFactory =
            new ThreadLocal<XMLEventFactory>() {
                
                @Override
                protected XMLEventFactory initialValue() {
                    return XMLEventFactory.newInstance();
                }
            };
    
    @Override
    protected String engineGetURI() {
        return ALGORITHM_URN;
    }
    
    @Override
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput argInput,
            OutputStream argOutput, Transform argTransform) throws IOException,
            CanonicalizationException, InvalidCanonicalizerException,
            TransformationException, ParserConfigurationException, SAXException {
        
        process(argInput.getOctetStream(), argOutput);
        XMLSignatureInput result = new XMLSignatureInput((byte[]) null);
        result.setOutputStream(argOutput);
        return result;
        
    }
    
    @Override
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput argInput,
            Transform argTransform) throws IOException, CanonicalizationException,
            InvalidCanonicalizerException, TransformationException,
            ParserConfigurationException, SAXException {
        
        return enginePerformTransform(argInput);
    }
    
    @Override
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput argInput)
            throws IOException, CanonicalizationException,
            InvalidCanonicalizerException, TransformationException,
            ParserConfigurationException, SAXException {
        
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        process(argInput.getOctetStream(), result);
        byte[] postTransformData = result.toByteArray();
        
        return new XMLSignatureInput(postTransformData);
    }
    
    public void process(InputStream argSrc, OutputStream argDst) throws TransformationException {
        
        DebugOutputStream debugStream = null;
        
        Stack<List<Namespace>> prefixMappingStack = new Stack<List<Namespace>>();
        int prefixCnt = 1;
        XMLEventReader src = null;
        XMLEventWriter dst = null;
        try {
            src = inputFactory.get().createXMLEventReader(argSrc, ENCODING_UTF_8);
            if (logger.isDebugEnabled()) {
                debugStream = new DebugOutputStream(argDst);
                dst = outputFactory.get().createXMLEventWriter(debugStream, ENCODING_UTF_8);
            } else {
                dst = outputFactory.get().createXMLEventWriter(argDst, ENCODING_UTF_8);
            }
            XMLEventFactory factory = eventFactory.get();
            
            while (src.hasNext()) {
                XMLEvent event = src.nextEvent();
                
                if (event.isCharacters()) {
                    String data = event.asCharacters().getData();
                    // Отсекаем возвраты каретки и пробельные строки.
                    if (!data.trim().isEmpty()) {
                        dst.add(event);
                    }
                    continue;
                } else if (event.isStartElement()) {
                    List<Namespace> myPrefixMappings = new LinkedList<Namespace>();
                    prefixMappingStack.push(myPrefixMappings);
                    
                    // Обработка элемента: NS prefix rewriting.
                    // N.B. Элементы в unqualified form не поддерживаются.
                    StartElement srcEvent = (StartElement) event;
                    String nsURI = srcEvent.getName().getNamespaceURI();
                    String prefix = findPrefix(nsURI, prefixMappingStack);
                    
                    if (prefix == null) {
                        prefix = NS_PREFIX + String.valueOf(prefixCnt++);
                        myPrefixMappings.add(factory.createNamespace(prefix, nsURI));
                    }
                    StartElement dstEvent = factory.createStartElement(
                            prefix, nsURI, srcEvent.getName().getLocalPart());
                    dst.add(dstEvent);
                    
                    // == Обработка атрибутов. Два шага: отсортировать, промэпить namespace URI. 
                    
                    Iterator<Attribute> srcAttributeIterator = srcEvent.getAttributes();
                    // Положим атрибуты в list, чтобы их можно было отсортировать.
                    List<Attribute> srcAttributeList = new LinkedList<Attribute>();
                    while (srcAttributeIterator.hasNext()) {
                        srcAttributeList.add(srcAttributeIterator.next());
                    }
                    // Сортировка атрибутов по алфавиту.
                    Collections.sort(srcAttributeList, attributeSortingComparator);
                    
                    // Обработка префиксов. Аналогична обработке префиксов элементов,
                    // за исключением того, что у атрибут может не иметь namespace.
                    List<Attribute> dstAttributeList = new LinkedList<Attribute>();
                    for (Attribute srcAttribute : srcAttributeList) {
                        String attributeNsURI = srcAttribute.getName().getNamespaceURI();
                        String attributeLocalName = srcAttribute.getName().getLocalPart();
                        String value = srcAttribute.getValue();
                        String attributePrefix = null;
                        Attribute dstAttribute = null;
                        if (attributeNsURI != null && !"".equals(attributeNsURI)) {
                            attributePrefix = findPrefix(attributeNsURI, prefixMappingStack);
                            if (attributePrefix == null) {
                                attributePrefix = NS_PREFIX + String.valueOf(prefixCnt++);
                                myPrefixMappings.add(factory.createNamespace(
                                        attributePrefix, attributeNsURI));
                            }
                            dstAttribute = factory.createAttribute(
                                    attributePrefix, attributeNsURI, attributeLocalName, value);
                        } else {
                            dstAttribute = factory.createAttribute(attributeLocalName, value);
                        }
                        dstAttributeList.add(dstAttribute);
                    }
                    
                    // Высести namespace prefix mappings для текущего элемента.
                    // Их порядок детерминирован, т.к. перед мэппингом атрибуты 
                    // были отсортированы.
                    // Поэтому дополнительной сотрировки здесь не нужно.
                    for (Namespace mapping : myPrefixMappings) {
                        dst.add(mapping);
                    }
                    
                    // Вывести атрибуты. 
                    // N.B. Мы не выводим атрибуты сразу вместе с элементом, используя метод
                    // XMLEventFactory.createStartElement(prefix, nsURI, localName,
                    //   List<Namespace>, List<Attribute>),
                    // потому что при использовании этого метода порядок атрибутов 
                    // в выходном документе меняется произвольным образом.
                    for (Attribute attr : dstAttributeList) {
                        dst.add(attr);
                    }
                    
                    continue;
                } else if (event.isEndElement()) {
                    // Гарантируем, что empty tags запишутся в форме <a></a>, а не в форме <a/>.
                    dst.add(eventFactory.get().createSpace(""));
                    
                    // NS prefix rewriting
                    EndElement srcEvent = (EndElement) event;
                    String nsURI = srcEvent.getName().getNamespaceURI();
                    String prefix = findPrefix(nsURI, prefixMappingStack);
                    if (prefix == null) {
                        throw new TransformationException(
                                "EndElement: prefix mapping is not found for namespace " + nsURI);
                    }
                    
                    EndElement dstEvent = eventFactory.get().
                            createEndElement(prefix, nsURI, srcEvent.getName().getLocalPart());
                    dst.add(dstEvent);
                    
                    prefixMappingStack.pop();
                    
                    continue;
                } else if (event.isAttribute()) {
                    // Атрибуты обрабатываются в событии startElement.
                    continue;
                }
                
                // Остальные события (processing instructions, start document, etc.) 
                // нас не интересуют.
            }
        } catch (XMLStreamException e) {
            Object exArgs[] = {e.getMessage()};
            throw new TransformationException(
                    "Can not perform transformation " + ALGORITHM_URN, exArgs, e);
        } finally {
            if (src != null) {
                try {
                    src.close();
                } catch (XMLStreamException e) {
                    logger.warn("Can not close XMLEventReader", e);
                }
            }
            if (dst != null) {
                try {
                    dst.close();
                } catch (XMLStreamException e) {
                    logger.warn("Can not close XMLEventWriter", e);
                }
            }
            try {
                argSrc.close();
            } catch (IOException e) {
                logger.warn("Can not close input stream.", e);
            }
            try {
                argDst.close();
            } catch (IOException e) {
                logger.warn("Can not close output stream.", e);
            }
            
            if (logger.isDebugEnabled()) {
                try {
                    String contentAfterCanonizationAndTransforms =
                            new String(debugStream.getCollectedData(), "UTF-8");
                    logger.debug("Content after canonization: " +
                            contentAfterCanonizationAndTransforms);
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    private String findPrefix(String argNamespaceURI, Stack<List<Namespace>> argMappingStack) {
        if (argNamespaceURI == null) {
            throw new IllegalArgumentException("No namespace элементы не поддерживаются.");
        }
        
        for (List<Namespace> elementMappingList : argMappingStack) {
            for (Namespace mapping : elementMappingList) {
                if (argNamespaceURI.equals(mapping.getNamespaceURI())) {
                    return mapping.getPrefix();
                }
            }
        }
        return null;
    }
    
    private static class AttributeSortingComparator implements Comparator<Attribute> {
        
        @Override
        public int compare(Attribute x, Attribute y) {
            String xNS = x.getName().getNamespaceURI();
            String xLocal = x.getName().getLocalPart();
            String yNS = y.getName().getNamespaceURI();
            String yLocal = y.getName().getLocalPart();
            
            // Сначала сравниваем namespaces.
            if (xNS == null || xNS.equals("")) {
                if (yNS != null && !"".equals(xNS)) {
                    return 1;
                }
            } else {
                if (yNS == null || "".equals(yNS)) {
                    return -1;
                } else {
                    int nsComparisonResult = xNS.compareTo(yNS);
                    if (nsComparisonResult != 0) {
                        return nsComparisonResult;
                    }
                }
            }
            
            // Если namespaces признаны эквивалентными, сравниваем local names.
            return xLocal.compareTo(yLocal);
        }
    }
    
    private static class DebugOutputStream extends OutputStream {
        
        private ByteArrayOutputStream collector = new ByteArrayOutputStream();
        private OutputStream wrappedStream;
        
        public DebugOutputStream(OutputStream arg) {
            wrappedStream = arg;
        }
        
        public byte[] getCollectedData() {
            try {
                collector.flush();
            } catch (IOException e) {
            }
            return collector.toByteArray();
        }
        
        @Override
        public void write(int b) throws IOException {
            collector.write(b);
            wrappedStream.write(b);
        }
        
        @Override
        public void close() throws IOException {
            collector.close();
            wrappedStream.close();
            super.close();
        }
        
        @Override
        public void flush() throws IOException {
            collector.flush();
            wrappedStream.flush();
        }
        
    }
    
    public static void main(String[] args) throws IOException, CanonicalizationException,
            InvalidCanonicalizerException, TransformationException,
            ParserConfigurationException, SAXException, XMLSignatureException, TransformerConfigurationException,
            TransformerException, InvalidTransformException
    {
        // TODO Auto-generated method stub
        System.out.println("Hello World");
        org.apache.xml.security.Init.init();
        SmevTransformSpi transform = new SmevTransformSpi();
        
        String xmlText = "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\">\r\n" +
                "   <S:Body>\r\n" +
                "      <ns2:SendRequestRequest xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\" xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\">\r\n" +
                "         <ns:SenderProvidedRequestData Id=\"SIGNED_BY_CONSUMER\" xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns:ns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\">      <ns:MessageID>db0486d0-3c08-11e5-95e2-d4c9eff07b77</ns:MessageID><ns2:MessagePrimaryContent><ns1:BreachRequest xmlns:ns1=\"urn://x-artefacts-gibdd-gov-ru/breach/root/1.0\"  xmlns:ns2=\"urn://x-artefacts-gibdd-gov-ru/breach/commons/1.0\"  xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" Id=\"PERSONAL_SIGNATURE\"> <ns1:RequestedInformation> <ns2:RegPointNum>Т785ЕС57</ns2:RegPointNum> </ns1:RequestedInformation> <ns1:Governance> <ns2:Name>ГИБДД РФ</ns2:Name> <ns2:Code>GIBDD</ns2:Code> <ns2:OfficialPerson> <ns3:FamilyName>Загурский</ns3:FamilyName> <ns3:FirstName>Андрей</ns3:FirstName> <ns3:Patronymic>Петрович</ns3:Patronymic> </ns2:OfficialPerson></ns1:Governance> </ns1:BreachRequest> </ns2:MessagePrimaryContent>  <ns:TestMessage/></ns:SenderProvidedRequestData>\r\n" +
                "         <ns2:CallerInformationSystemSignature></ns2:CallerInformationSystemSignature>\r\n" +
                "      </ns2:SendRequestRequest>\r\n" +
                "   </S:Body>\r\n" +
                "</S:Envelope>";
        InputStream is = new ByteArrayInputStream(xmlText.getBytes());
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document d = db.parse(is);
        
        Node rootElement = d.getDocumentElement();
        System.out.println("Input:");
        System.out.println(nodeToString(rootElement));
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Source xmlSource = new DOMSource(rootElement);
        Result outputTarget = new StreamResult(outputStream);
        TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
        
        ByteArrayOutputStream outputStrem = new ByteArrayOutputStream();
        
        XMLSignatureInput xml = new XMLSignatureInput(inputStream);
        String test = new String();
        
        Transform t1 = new Transform(d, Transforms.TRANSFORM_XPATH);
        
        //  xml = transform.enginePerformTransform(xml, outputStrem, t1);
        transform.process(inputStream, outputStrem);
        System.out.println("Output:");
        System.out.println(outputStrem.toString());
        
        //System.out.println(xmlText);
    }
    
    private static String nodeToString(Node node) {
        StringWriter sw = new StringWriter();
        try {
            Transformer t = TransformerFactory.newInstance().newTransformer();
            t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            t.setOutputProperty(OutputKeys.INDENT, "yes");
            t.transform(new DOMSource(node), new StreamResult(sw));
        } catch (TransformerException te) {
            System.out.println("nodeToString Transformer Exception");
        }
        return sw.toString();
    }
}
